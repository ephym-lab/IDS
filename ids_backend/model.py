"""
model.py
--------
Loads the Keras MLP model once at startup via FastAPI lifespan.
Exposes a predict() function used by all endpoints and the capture thread.
"""

import os
import numpy as np

# ---------------------------------------------------------------------------
# Artefact path
# ---------------------------------------------------------------------------
_MODEL_PATH = os.path.join(os.path.dirname(__file__), "models_dir", "ids_mlp_model.keras")

# Will be set to the loaded Keras model by load_model()
_model = None


def load_model() -> None:
    """
    Load the Keras model from disk.
    Must be called once at application startup (inside the lifespan context).
    """
    global _model
    # Import here so TF initialisation only happens when explicitly called
    import tensorflow as tf

    _model = tf.keras.models.load_model(_MODEL_PATH)


def predict(features: np.ndarray) -> tuple[str, float]:
    """
    Run inference on a preprocessed feature array.

    Parameters
    ----------
    features : np.ndarray
        Shape (1, 183), dtype float32 — output of preprocessor.preprocess()

    Returns
    -------
    (class_label, confidence)
        class_label : str  — human-readable class name from the LabelEncoder
        confidence  : float — max softmax probability (0-1)
    """
    if _model is None:
        raise RuntimeError("Model has not been loaded. Call load_model() first.")

    from preprocessor import decode_label  # avoid circular import at module level

    probs = _model.predict(features, verbose=0)  # shape (1, n_classes)
    class_index = int(np.argmax(probs, axis=1)[0])
    confidence = float(np.max(probs))
    class_label = decode_label(class_index)
    return class_label, confidence
