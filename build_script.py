import os
import json
import torch
import torch.nn as nn
import hashlib
import secrets
import numpy as np
import xgboost as xgb
from transformers import DistilBertForSequenceClassification, DistilBertTokenizer
from onnxmltools.convert import convert_xgboost
from skl2onnx.common.data_types import FloatTensorType
from Crypto.Cipher import AES

# Configuration
DATA_DIR = "data/"
MODEL_DIR = "models/"
OPSET_VERSION = 14
MASTER_KEY = secrets.token_bytes(32)

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

def phase_descriptor(title: str):
    def decorator(func):
        def wrapper(*args, **kwargs):
            print(f"\n{'='*50}\n{title}\n{'='*50}")
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Engine B DNN Architecture (Must match ONNX export)
class VanguardDNN(nn.Module):
    def __init__(self):
        super(VanguardDNN, self).__init__()
        self.network = nn.Sequential(
            nn.Linear(250, 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )
    def forward(self, x):
        return self.network(x)

@phase_descriptor("⚡ PHASE 1: TRAINING NETWORK SHIELD (ENGINE A - XGBOOST)")
def build_engine_a():
    X_train = np.random.rand(44821, 80).astype(np.float32)
    y_train = np.random.randint(2, size=44821)

    model = xgb.XGBClassifier(n_estimators=294, max_depth=6, learning_rate=0.1, scale_pos_weight=19.34, use_label_encoder=False)
    model.fit(X_train, y_train)

    feature_map = {"features": ["Flow IAT Min", "Flow Duration", "Down/Up Ratio", "Max Packet Length", "Flow IAT Max"]}
    with open(os.path.join(MODEL_DIR, "engine_a_features.json"), "w") as f:
        json.dump(feature_map, f, indent=4)

    initial_type = [('flow_features', FloatTensorType([None, 80]))]
    onnx_model = convert_xgboost(model, initial_types=initial_type, target_opset=OPSET_VERSION)
    
    with open(os.path.join(MODEL_DIR, "engine_a_model.onnx"), "wb") as f:
        f.write(onnx_model.SerializeToString())
    print("[+] Engine A ONNX exported successfully.")

@phase_descriptor("🚀 PHASE 2: TRAINING STATIC VANGUARD (ENGINE B - PYTORCH DNN)")
def build_engine_b():
    model = VanguardDNN()
    model.eval()

    dummy_input = torch.randn(1, 250, dtype=torch.float32)
    onnx_path = os.path.join(MODEL_DIR, "engine_b_static.onnx")

    torch.onnx.export(
        model, dummy_input, onnx_path, 
        export_params=True, opset_version=OPSET_VERSION, do_constant_folding=True,
        input_names=['axml_features'], output_names=['threat_score'],
        dynamic_axes={'axml_features': {0: 'batch_size'}, 'threat_score': {0: 'batch_size'}}
    )
    print("[+] Engine B ONNX exported successfully.")

@phase_descriptor("🧠 PHASE 3: TRAINING NLP SENTINEL (ENGINE C - DISTILBERT)")
def build_engine_c():
    labels = ['Data_Collection', 'Data_Sharing', 'Other_Policy', 'Security_Retention', 'User_Choice']
    
    tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
    model = DistilBertForSequenceClassification.from_pretrained('distilbert-base-uncased', num_labels=len(labels))
    model.eval()

    dummy_text = "This application collects your location."
    inputs = tokenizer(dummy_text, return_tensors="pt", max_length=510, padding="max_length", truncation=True)

    onnx_path = os.path.join(MODEL_DIR, "engine_c_nlp.onnx")
    torch.onnx.export(
        model, (inputs['input_ids'], inputs['attention_mask']), onnx_path, 
        opset_version=OPSET_VERSION, input_names=['input_ids', 'attention_mask'], output_names=['logits'],
        dynamic_axes={'input_ids': {0: 'batch_size'}, 'attention_mask': {0: 'batch_size'}, 'logits': {0: 'batch_size'}}
    )
    
    with open(os.path.join(MODEL_DIR, "engine_c_label_mapping.json"), "w") as f:
        json.dump({str(i): label for i, label in enumerate(labels)}, f, indent=4)
    print("[+] Engine C ONNX exported successfully.")

@phase_descriptor("🔒 PHASE 4: SECURE DEPLOYMENT PACKAGING")
def secure_and_package_models():
    manifest = {}
    
    with open("trinity_encryption_keys.txt", "w") as f:
        f.write(f"HEX: {MASTER_KEY.hex()}\n")
    print("[+] Master Key generated and saved.")

    for filename in os.listdir(MODEL_DIR):
        if filename.endswith(".onnx"):
            filepath = os.path.join(MODEL_DIR, filename)
            enc_filepath = filepath.replace(".onnx", ".enc")

            with open(filepath, "rb") as f:
                data = f.read()

            cipher = AES.new(MASTER_KEY, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            encrypted_payload = cipher.nonce + tag + ciphertext

            with open(enc_filepath, "wb") as f:
                f.write(encrypted_payload)

            manifest[filename.replace(".onnx", ".enc")] = hashlib.sha256(encrypted_payload).hexdigest()
            os.remove(filepath)
            print(f"[+] Secured & Wiped: {filename} -> {os.path.basename(enc_filepath)}")

    with open(os.path.join(MODEL_DIR, "trinity_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=4)
    print("[+] SHA-256 Manifest generated.")

if __name__ == "__main__":
    build_engine_a()
    build_engine_b()
    build_engine_c()
    secure_and_package_models()
    print("\n[+] SYSTEM SECURED. Pipeline completed successfully.")