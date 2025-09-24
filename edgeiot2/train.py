import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report
from keras.models import Sequential
from keras.layers import Dense, Dropout
from keras.callbacks import EarlyStopping
from imblearn.over_sampling import SMOTE
import joblib
import json
import os
import hashlib

# Bot-IoT aligned features (6 generalizable features; IPs removed)
SELECTED_FEATURES = [
    'pkts',   # Number of packets in flow
    'bytes',  # Total bytes transferred
    'dur',    # Flow duration in seconds
    'rate',   # Packet rate (packets/second)
    'sport',  # Source port number
    'dport'   # Destination port number
]

# Classes we train on (no DDoS; DDoS collapsed to DoS)
ATTACK_TYPES = ['Normal', 'DoS', 'Reconnaissance', 'Theft']


def normalize_class_name(name: str) -> str:
    """Normalize labels to standard categories. Merge any DDoS into DoS."""
    s = str(name).strip().lower()
    if 'normal' in s or s == '0':
        return 'Normal'
    if 'ddos' in s:
        return 'DoS'  # collapse DDoS into DoS
    if 'dos' in s and 'ddos' not in s:
        return 'DoS'
    if 'recon' in s or 'scan' in s or 'service_scan' in s or 'os_scan' in s:
        return 'Reconnaissance'
    if 'theft' in s or 'exfil' in s or 'data' in s or 'keylogging' in s:
        return 'Theft'
    # Default mapping for other attacks
    return 'DoS'


def safe_float(x, default=0.0):
    """Safely convert to float."""
    try:
        if isinstance(x, (list, dict)):
            return default
        return float(x)
    except (ValueError, TypeError):
        return default


def clean_and_prepare_data(df, target_column):
    """Clean and prepare the dataset."""
    print(f"Original dataset shape: {df.shape}")
    print(f"Target column: {target_column}")
    try:
        print(f"Sample target values:\n{df[target_column].value_counts().head()}")
    except Exception:
        pass

    # Handle port columns
    for port_col in ['sport', 'dport']:
        if port_col in df.columns:
            print(f"Processing {port_col} column...")

            def convert_port(val):
                if pd.isna(val) or isinstance(val, (list, dict)):
                    return 0
                try:
                    if isinstance(val, str):
                        val = val.strip()
                        if val.lower().startswith('0x'):
                            return int(val, 16)
                    return int(float(val))
                except Exception:
                    return 0

            df[port_col] = df[port_col].apply(convert_port)

    # Handle other numeric columns
    for col in ['pkts', 'bytes', 'dur', 'rate']:
        if col in df.columns:
            print(f"Processing {col} column...")
            df[col] = df[col].apply(lambda x: safe_float(x, 0.0))

    # Clean target column
    if target_column in df.columns:
        print(f"Processing target column {target_column}...")
        df[target_column] = df[target_column].apply(
            lambda x: str(x) if not isinstance(x, (list, dict)) else 'Normal'
        )

    # Remove rows with all-zero dynamic features or invalid target
    print("Removing invalid rows...")

    # Only consider dynamic flow features for zero-row filtering
    dynamic_cols = [c for c in ['pkts', 'bytes', 'dur', 'rate'] if c in df.columns]
    if dynamic_cols:
        feature_sum = df[dynamic_cols].sum(axis=1, numeric_only=True)
        df = df[feature_sum > 0]

    # Remove rows with null target
    df = df.dropna(subset=[target_column])

    print(f"Cleaned dataset shape: {df.shape}")
    return df


def train_model(data_files, multiclass=True, model_path='ann_model.h5',
                scaler_path='scaler.pkl', class_names_path='class_names.json'):
    """Train ANN model on Bot-IoT dataset."""

    print("Loading datasets...")
    df_list = []
    for file_path in data_files:
        if os.path.exists(file_path):
            print(f"Loading {file_path}...")
            try:
                df_temp = pd.read_csv(file_path, low_memory=False)
                print(f"Loaded {len(df_temp)} rows from {file_path}")
                df_list.append(df_temp)
            except Exception as e:
                print(f"Error loading {file_path}: {e}")
        else:
            print(f"File not found: {file_path}")

    if not df_list:
        raise Exception("No valid data files found!")

    # Combine datasets
    df = pd.concat(df_list, ignore_index=True)
    print(f"Combined dataset shape: {df.shape}")
    print(f"Dataset columns: {list(df.columns)}")

    # Find target column (prefer category for multiclass)
    if multiclass:
        possible_targets = ['category', 'Category', 'subcategory', 'Subcategory', 'label', 'Label', 'attack', 'Attack']
    else:
        possible_targets = ['attack', 'Attack', 'label', 'Label', 'category', 'Category', 'subcategory', 'Subcategory']

    target_column = next((col for col in possible_targets if col in df.columns), None)
    if not target_column:
        raise Exception(f'No target column found! Available columns: {list(df.columns)}')
    print(f"Target column: {target_column}")

    # Clean and prepare data
    df = clean_and_prepare_data(df, target_column)

    # Check which features are available
    available_features = [col for col in SELECTED_FEATURES if col in df.columns]
    missing_features = [col for col in SELECTED_FEATURES if col not in df.columns]

    print(f"Available features: {available_features}")
    if missing_features:
        print(f"Missing features: {missing_features}")

    if len(available_features) < 4:
        raise Exception("Insufficient features available for training!")

    # Prepare features and target
    X = df[available_features].values.astype(float)
    y_raw = df[target_column].values

    print(f"Feature matrix shape: {X.shape}")
    print(f"Target distribution:\n{pd.Series(y_raw).value_counts()}")

    # Normalize labels and build index mapping with stable order ATTACK_TYPES
    if multiclass:
        print("Training multiclass model...")
        y_labels = np.array([normalize_class_name(label) for label in y_raw])

        # Stable, desired order based on ATTACK_TYPES (filters to present classes)
        present = sorted(set(y_labels), key=lambda x: ATTACK_TYPES.index(x) if x in ATTACK_TYPES else 999)
        class_names = present
        class_to_idx = {cls: idx for idx, cls in enumerate(class_names)}
        y = np.array([class_to_idx[cls] for cls in y_labels])
        num_classes = len(class_names)
    else:
        print("Training binary model...")
        y = np.array([0 if normalize_class_name(label) == 'Normal' else 1 for label in y_raw])
        class_names = ['Normal', 'Attack']
        num_classes = 2

    print(f"Final target distribution:\n{pd.Series(y).value_counts()}")

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Feature scaling
    print("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Save scaler
    joblib.dump(scaler, scaler_path)
    print(f"Scaler saved to {scaler_path}")

    # Apply SMOTE for class balancing
    print("Applying SMOTE for class balancing...")
    smote = SMOTE(random_state=42)
    X_train_balanced, y_train_balanced = smote.fit_resample(X_train_scaled, y_train)
    print(f"After SMOTE: {X_train_balanced.shape}")
    print(f"Balanced target distribution:\n{pd.Series(y_train_balanced).value_counts()}")

    # Build model
    print("Building neural network...")
    if multiclass and num_classes > 2:
        # Multiclass model
        model = Sequential([
            Dense(64, activation='relu', input_shape=(X_train_balanced.shape[1],)),
            Dropout(0.3),
            Dense(32, activation='relu'),
            Dropout(0.2),
            Dense(16, activation='relu'),
            Dropout(0.1),
            Dense(num_classes, activation='softmax')
        ])
        model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
    else:
        # Binary model
        model = Sequential([
            Dense(32, activation='relu', input_shape=(X_train_balanced.shape[1],)),
            Dropout(0.2),
            Dense(16, activation='relu'),
            Dropout(0.1),
            Dense(1, activation='sigmoid')
        ])
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

    print("Model architecture:")
    model.summary()

    # Train model
    print("Training model...")
    early_stopping = EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)

    history = model.fit(
        X_train_balanced, y_train_balanced,
        validation_data=(X_test_scaled, y_test),
        epochs=50,
        batch_size=256,
        callbacks=[early_stopping],
        verbose=1
    )

    # Evaluate model
    print("\nEvaluating model...")
    if multiclass and num_classes > 2:
        y_pred_proba = model.predict(X_test_scaled, verbose=0)
        y_pred = np.argmax(y_pred_proba, axis=1)

        accuracy = accuracy_score(y_test, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, y_pred, average='weighted', zero_division=0
        )

        print(f"Test Accuracy: {accuracy:.4f}")
        print(f"Test Precision (weighted): {precision:.4f}")
        print(f"Test Recall (weighted): {recall:.4f}")
        print(f"Test F1-Score (weighted): {f1:.4f}")

        print("\nDetailed Classification Report:")
        print(classification_report(
            y_test, y_pred,
            labels=list(range(num_classes)),
            target_names=class_names,
            zero_division=0
        ))
    else:
        y_pred_proba = model.predict(X_test_scaled, verbose=0).ravel()
        y_pred = (y_pred_proba >= 0.5).astype(int)

        accuracy = accuracy_score(y_test, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, y_pred, average='binary', zero_division=0
        )

        print(f"Test Accuracy: {accuracy:.4f}")
        print(f"Test Precision: {precision:.4f}")
        print(f"Test Recall: {recall:.4f}")
        print(f"Test F1-Score: {f1:.4f}")

        print("\nDetailed Classification Report:")
        print(classification_report(
            y_test, y_pred,
            labels=[0, 1],
            target_names=class_names,
            zero_division=0
        ))

    # Save model
    model.save(model_path)
    print(f"Model saved to {model_path}")

    # Save class names
    with open(class_names_path, 'w') as f:
        json.dump(class_names, f)
    print(f"Class names saved to {class_names_path}")

    # Print feature information
    print(f"\nModel trained with {len(available_features)} features:")
    for i, feature in enumerate(available_features):
        print(f"  {i}: {feature}")

    if missing_features:
        print(f"\nNote: Missing features will be zero-padded during inference:")
        for feature in missing_features:
            print(f"  - {feature}")

    return model, scaler, class_names, available_features


def main():
    """Main training function"""
    # Update these paths to your dataset files
    data_files = [
        'data_1.csv',
        'data_2.csv',
        # 'data_3.csv',  # add back when the CSV is fixed if it had parsing errors
    ]

    print("=" * 60)
    print("Bot-IoT Dataset ANN Training (6 features, multiclass on category)")
    print("=" * 60)

    try:
        # Train multiclass model (recommended)
        print("\nTraining multiclass model...")
        model, scaler, class_names, features = train_model(
            data_files=data_files,
            multiclass=True,
            model_path='ann_model.h5',
            scaler_path='scaler.pkl',
            class_names_path='class_names.json'
        )

        print("\n" + "=" * 60)
        print("TRAINING COMPLETED SUCCESSFULLY!")
        print("=" * 60)
        print(f"Model: ann_model.h5")
        print(f"Scaler: scaler.pkl")
        print(f"Classes: {class_names}")
        print(f"Features: {features}")
        print("\nFiles ready for use with the NIDS application!")

    except Exception as e:
        print(f"\nTraining failed: {e}")
        print("\nTrying binary classification as fallback...")

        try:
            # Fallback to binary model
            model, scaler, class_names, features = train_model(
                data_files=data_files,
                multiclass=False,
                model_path='ann_model_binary.h5',
                scaler_path='scaler_binary.pkl',
                class_names_path='class_names_binary.json'
            )
            print("\n" + "=" * 60)
            print("BINARY TRAINING COMPLETED!")
            print("=" * 60)
            print("Use ann_model_binary.h5 with the NIDS application")

        except Exception as e2:
            print(f"\nBinary training also failed: {e2}")
            print("\nPlease check your dataset files and column names.")


if __name__ == "__main__":
    main()