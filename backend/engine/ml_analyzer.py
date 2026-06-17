"""Machine Learning based text analysis for phishing detection."""

import asyncio
import logging
import threading
from typing import List

from backend.models.schemas import Finding

# These will be imported inside the class to avoid slowing down app startup if ML is disabled
# from transformers import pipeline

logger = logging.getLogger(__name__)


class MLAnalyzer:
    def __init__(self):
        self.model_name = "ealvaradob/phishing-email-detection"
        self._classifier = None
        self._lock = threading.Lock()
        self._loaded = False
        self._failed = False

    def _load_model(self):
        """Load the model synchronously. Should be called in a thread."""
        if self._loaded or self._failed:
            return

        with self._lock:
            # Double checked locking
            if self._loaded or self._failed:
                return

            try:
                from transformers import pipeline
                logger.info(f"Loading ML model '{self.model_name}'...")
                # We use pipeline for text classification
                self._classifier = pipeline(
                    "text-classification",
                    model=self.model_name,
                    tokenizer=self.model_name,
                    truncation=True,
                    max_length=512,
                )
                self._loaded = True
                logger.info("ML model loaded successfully.")
            except Exception as e:
                logger.error(f"Failed to load ML model: {e}")
                self._failed = True

    async def analyze(self, text: str) -> List[Finding]:
        """
        Analyze email text using the ML model.
        Returns a list of Finding objects compatible with other analyzers.
        """
        findings: List[Finding] = []
        if not text.strip():
            return findings

        # Load model in a background thread if not loaded
        if not self._loaded and not self._failed:
            await asyncio.to_thread(self._load_model)

        if self._failed or not self._classifier:
            return findings

        try:
            # Run inference in a background thread to avoid blocking the event loop
            result = await asyncio.to_thread(self._classifier, text)

            # The model usually returns something like [{'label': 'Phishing Email', 'score': 0.99}]
            # Or LABEL_0 / LABEL_1
            if result and len(result) > 0:
                prediction = result[0]
                label = prediction.get("label", "").lower()
                score = prediction.get("score", 0.0)

                # Check if it's classified as phishing
                is_phishing = False
                if "phishing" in label or label == "label_1":
                    is_phishing = True

                if is_phishing and score > 0.6:
                    # Map ML confidence to severity
                    if score > 0.9:
                        severity = "critical"
                    elif score > 0.8:
                        severity = "high"
                    elif score > 0.7:
                        severity = "medium"
                    else:
                        severity = "low"

                    findings.append(
                        Finding(
                            category="content",
                            severity=severity,
                            title="AI Phishing Detection",
                            description=f"Our Machine Learning model classified this email as phishing with {score:.1%} confidence.",
                            evidence=f"Model: {self.model_name} | Score: {score:.3f}",
                        )
                    )
                elif not is_phishing and score > 0.8:
                    # Provide an info finding if strongly safe
                    findings.append(
                        Finding(
                            category="content",
                            severity="info",
                            title="AI Clean Detection",
                            description=f"Our Machine Learning model classified this email as safe with {score:.1%} confidence.",
                            evidence=f"Model: {self.model_name} | Score: {score:.3f}",
                        )
                    )

        except Exception as e:
            logger.error(f"ML analysis error: {e}")

        return findings


# Singleton instance
ml_analyzer = MLAnalyzer()
