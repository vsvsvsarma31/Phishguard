import xgboost as xgb
import joblib
from sklearn.model_selection import GridSearchCV
from sklearn.utils.class_weight import compute_sample_weight
from phishguard.ml.preprocess import load_and_preprocess, get_train_test_split
from sklearn.metrics import classification_report, accuracy_score

MODEL_PATH = "phishguard/ml/phish_model.joblib"

PARAM_GRID = {
    'n_estimators': [100, 200, 300],
    'max_depth': [4, 6, 8],
    'learning_rate': [0.05, 0.1, 0.2],
    'subsample': [0.8, 1.0],
    'colsample_bytree': [0.8, 1.0],
}

def tune_model(csv_path):
    X, y = load_and_preprocess(csv_path)
    X_train, X_test, y_train, y_test = get_train_test_split(X, y)

    sample_weights = compute_sample_weight(class_weight='balanced', y=y_train)

    base_model = xgb.XGBClassifier(
        objective='multi:softprob',
        num_class=4,
        random_state=42,
        use_label_encoder=False,
        eval_metric='mlogloss',
        tree_method='hist',
    )

    grid_search = GridSearchCV(
        estimator=base_model,
        param_grid=PARAM_GRID,
        scoring='accuracy',
        cv=3,
        n_jobs=-1,
        verbose=2,
    )

    grid_search.fit(X_train, y_train, sample_weight=sample_weights)

    print(f"\nBest parameters: {grid_search.best_params_}")
    print(f"Best CV accuracy: {grid_search.best_score_:.4f}")

    best_model = grid_search.best_estimator_
    y_pred = best_model.predict(X_test)
    print(f"\nTest accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:\n", classification_report(y_test, y_pred))

    joblib.dump(best_model, MODEL_PATH)
    print(f"Best model saved to {MODEL_PATH}")

    return grid_search.best_params_


if __name__ == "__main__":
    import os
    DATASET_PATH = "phishguard/malicious_phish.csv"
    if os.path.exists(DATASET_PATH):
        tune_model(DATASET_PATH)
    else:
        print(f"Dataset not found at {DATASET_PATH}")
