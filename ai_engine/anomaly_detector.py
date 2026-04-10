import pickle
import logging
import time
import threading
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from config.settings import (
    MODEL_PATH, CONTAMINATION, N_ESTIMATORS, TRAINING_SAMPLES,
    RISK_LOW_MAX, RISK_MEDIUM_MAX
)

logger = logging.getLogger(__name__)


class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self._is_trained = False
        self._lock = threading.Lock()
        self._feature_names = [
            "packet_count", "total_bytes", "unique_ports", "frequency",
            "unique_dst_ips", "syn_count", "syn_ratio", "bytes_per_packet",
        ]

    def _extract_features(self, ip_stats: dict) -> np.ndarray:
        features = []
        for ip, stats in ip_stats.items():
            packet_count = stats.get("packet_count", 0)
            total_bytes = stats.get("total_bytes", 0)
            unique_ports = stats.get("unique_ports", 0)
            frequency = stats.get("frequency", 0)
            unique_dst_ips = stats.get("unique_dst_ips", 0)
            syn_count = stats.get("syn_count", 0)
            syn_ratio = syn_count / max(packet_count, 1)
            bytes_per_packet = total_bytes / max(packet_count, 1)
            features.append([
                packet_count, total_bytes, unique_ports, frequency,
                unique_dst_ips, syn_count, syn_ratio, bytes_per_packet,
            ])
        if not features:
            return np.array([]).reshape(0, len(self._feature_names))
        return np.array(features)

    def train(self, training_data=None, n_samples=None):
        n_samples = n_samples or TRAINING_SAMPLES
        with self._lock:
            if training_data is None:
                logger.info("Generating synthetic training data")
                training_data = self._generate_synthetic_data(n_samples)

            X = np.array(training_data)
            if X.shape[0] == 0:
                logger.error("Empty training data")
                return False

            X_scaled = self.scaler.fit_transform(X)

            self.model = IsolationForest(
                n_estimators=N_ESTIMATORS,
                contamination=CONTAMINATION,
                random_state=42,
                n_jobs=-1,
            )
            self.model.fit(X_scaled)
            self._is_trained = True
            self._save_model()
            logger.info(f"Model trained on {X.shape[0]} samples")
            return True

    def _generate_synthetic_data(self, n_samples):
        rng = np.random.RandomState(42)
        normal = np.column_stack([
            rng.poisson(50, n_samples),
            rng.exponential(5000, n_samples),
            rng.poisson(3, n_samples),
            rng.exponential(2, n_samples),
            rng.poisson(2, n_samples),
            rng.poisson(1, n_samples),
            rng.beta(2, 20, n_samples),
            rng.exponential(500, n_samples),
        ])

        n_anomalies = int(n_samples * CONTAMINATION)
        anomalies = np.column_stack([
            rng.poisson(500, n_anomalies),
            rng.exponential(100000, n_anomalies),
            rng.poisson(50, n_anomalies),
            rng.exponential(50, n_anomalies),
            rng.poisson(20, n_anomalies),
            rng.poisson(100, n_anomalies),
            rng.beta(10, 2, n_anomalies),
            rng.exponential(5000, n_anomalies),
        ])

        return np.vstack([normal, anomalies])

    def predict(self, ip_stats: dict) -> dict:
        if not self._is_trained:
            logger.warning("Model not trained, training with synthetic data")
            self.train()

        with self._lock:
            X = self._extract_features(ip_stats)
            if X.shape[0] == 0:
                return {}

            X_scaled = self.scaler.transform(X)
            raw_scores = self.model.decision_function(X_scaled)
            predictions = self.model.predict(X_scaled)

            results = {}
            ips = list(ip_stats.keys())
            for i, ip in enumerate(ips):
                anomaly_score = -raw_scores[i]
                normalized_score = self._normalize_score(anomaly_score)
                risk_level = self._classify_risk(normalized_score)
                is_anomaly = predictions[i] == -1

                results[ip] = {
                    "risk_score": round(normalized_score, 4),
                    "risk_level": risk_level,
                    "is_anomaly": is_anomaly,
                    "raw_score": round(float(raw_scores[i]), 4),
                    "stats": ip_stats[ip],
                }
            return results

    def _normalize_score(self, score):
        return max(0.0, min(1.0, 1.0 / (1.0 + np.exp(-score))))

    def _classify_risk(self, score):
        if score <= RISK_LOW_MAX:
            return "faible"
        elif score <= RISK_MEDIUM_MAX:
            return "moyen"
        return "critique"

    def _save_model(self):
        try:
            MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(MODEL_PATH, "wb") as f:
                pickle.dump({"model": self.model, "scaler": self.scaler}, f)
            logger.info(f"Model saved to {MODEL_PATH}")
        except Exception as e:
            logger.error(f"Failed to save model: {e}")

    def load_model(self):
        try:
            if MODEL_PATH.exists():
                with open(MODEL_PATH, "rb") as f:
                    data = pickle.load(f)
                self.model = data["model"]
                self.scaler = data["scaler"]
                self._is_trained = True
                logger.info("Model loaded from disk")
                return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
        return False

    @property
    def is_trained(self):
        return self._is_trained

    def retrain(self, new_data: list = None, incremental: bool = False) -> bool:
        """Re-entraine le modele avec de nouvelles donnees.
        
        Args:
            new_data: Liste de vecteurs de features a ajouter au dataset d'entrainement
            incremental: Si True, ajoute les nouvelles donnees au modele existant
                        Si False, re-entraine depuis zero avec donnees + nouvelles donnees
        """
        with self._lock:
            logger.info("Starting model retraining...")
            
            if new_data is None:
                logger.info("No new data provided, using synthetic data for retraining")
                new_data = self._generate_synthetic_data(TRAINING_SAMPLES)
            
            try:
                if incremental and self._is_trained:
                    logger.info("Incremental training not fully supported, doing full retrain")
                
                training_data = np.array(new_data)
                
                if training_data.shape[1] != len(self._feature_names):
                    logger.error(f"Feature count mismatch: expected {len(self._feature_names)}, got {training_data.shape[1]}")
                    return False
                
                X_scaled = self.scaler.fit_transform(training_data)
                
                self.model = IsolationForest(
                    n_estimators=N_ESTIMATORS,
                    contamination=CONTAMINATION,
                    random_state=42,
                    n_jobs=-1,
                )
                self.model.fit(X_scaled)
                self._is_trained = True
                self._save_model()
                logger.info(f"Model retrained with {training_data.shape[0]} samples")
                return True
                
            except Exception as e:
                logger.error(f"Retraining failed: {e}")
                return False

    def retrain_with_false_positives(self, fp_features: list) -> bool:
        """Re-entraine le modele en tenant compte des faux positifs.
        
        Les faux positifs doivent etre des donnees 'normales' qu'on ajoute
        au dataset d'entrainement pour que le modele les reconnaisse comme tels.
        """
        if not fp_features:
            logger.info("No false positive features provided for retraining")
            return True
        
        synthetic_normal = self._generate_synthetic_data(TRAINING_SAMPLES)
        synthetic_anomalies = self._generate_synthetic_data(int(TRAINING_SAMPLES * CONTAMINATION))
        
        fp_data = np.array(fp_features)
        combined = np.vstack([synthetic_normal, synthetic_anomalies, fp_data])
        
        logger.info(f"Retraining with {len(fp_features)} false positive samples added")
        return self.retrain(new_data=combined.tolist())
