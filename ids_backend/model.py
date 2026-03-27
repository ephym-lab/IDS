"""
model.py
--------
Loads the Keras MLP model once at startup via FastAPI lifespan.
Exposes a predict() function used by all endpoints and the capture thread.
"""

import os
import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

# ---------------------------------------------------------------------------
# Artefact path
# ---------------------------------------------------------------------------
_MODEL_PATH = os.path.join(os.path.dirname(__file__), "models_dir", "ids_mlp_model(1).keras")

# Will be set to the loaded Keras model by load_model()
_model = None


def create_model_architecture():
    """
    Recreate the model architecture based on the configuration from the error
    """
    model = keras.Sequential([
        layers.Input(shape=(183,), name='input_layer'),
        layers.Dense(256, activation='relu', name='dense'),
        layers.BatchNormalization(name='batch_normalization'),
        layers.Dropout(0.4, name='dropout'),
        layers.Dense(128, activation='relu', name='dense_1'),
        layers.BatchNormalization(name='batch_normalization_1'),
        layers.Dropout(0.3, name='dropout_1'),
        layers.Dense(64, activation='relu', name='dense_2'),
        layers.Dropout(0.2, name='dropout_2'),
        layers.Dense(7, activation='softmax', name='dense_3')
    ])
    return model


def load_model() -> None:
    """
    Load the Keras model from disk by recreating architecture and loading weights.
    """
    global _model
    
    # Set environment variables
    os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
    
    try:
        # Try loading directly first
        _model = keras.models.load_model(_MODEL_PATH, compile=False)
        print("Model loaded directly")
    except Exception as e:
        print(f"Direct loading failed: {e}")
        print("Attempting to recreate architecture and load weights...")
        
        try:
            # Check if we have pre-extracted weights
            weights_path = _MODEL_PATH.replace('.keras', '.weights.h5')
            
            if not os.path.exists(weights_path):
                # Extract weights from .keras file
                import tempfile
                import zipfile
                
                print("Extracting weights from model file...")
                with tempfile.TemporaryDirectory() as tmpdir:
                    with zipfile.ZipFile(_MODEL_PATH, 'r') as zip_ref:
                        zip_ref.extractall(tmpdir)
                    
                    # Find and copy the weights file
                    for root, dirs, files in os.walk(tmpdir):
                        for file in files:
                            if file.endswith('.weights.h5'):
                                import shutil
                                shutil.copy(os.path.join(root, file), weights_path)
                                print(f"Saved weights to {weights_path}")
                                break
            
            # Create architecture and load weights
            _model = create_model_architecture()
            _model.load_weights(weights_path)
            print("Model loaded successfully with weights")
                    
        except Exception as e2:
            print(f"Architecture recreation failed: {e2}")
            raise RuntimeError(f"Could not load model: {e2}")


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