from flask import Blueprint, Flask, request, redirect, jsonify, render_template, current_app, send_file
import io
import mysql.connector
import threading
import numpy as np
import os
import pandas as pd
from werkzeug.utils import secure_filename
import tensorflow as tf
from keras.models import load_model
from preprocessing.preprocess import preprocess_csv
from website.livecapture import live_results, start_capture_thread, metrics, get_available_interfaces

cnn = Blueprint('cnn', __name__)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Ensure upload folder exists

# Load your trained CNN model
MODEL_PATH = 'model/CNNUpdate.h5'
model = load_model(MODEL_PATH)
# Ensure the model is loaded correctly
if model is None:
    raise ValueError(f"Model could not be loaded from {MODEL_PATH}")


def predict_anomalies(df):
    # Preprocess the DataFrame as needed
    # Example: df = df[['feature1', 'feature2']].values
    predictions = model.predict(df)
    # Post-process predictions
    df['Attack'] = predictions > 0.5  # Example threshold
    return df

from .myDataPreprocessing import myPreprocessor  # Adjust import as needed


# @cnn.route('/upload_traffics', methods=['POST'])
# def upload_traffic():
#     if 'csv_file' not in request.files:
#         return redirect(request.referrer)
#     file = request.files['csv_file']
#     if file.filename == '':
#         return redirect(request.referrer)
#     filename = secure_filename(file.filename)
#     filepath = os.path.join(, filename)
#     file.save(filepath)
#     df = pd.read_csv(filepath)

#     df_preprocessed, _ = myPreprocessor(df,'mean','label')  # Adjust label as needed
#     # Ensure df_preprocessed is in the correct format for your model
#     if df_preprocessed.empty:
#         return jsonify({'error': 'No data to process'}), 400
#     # Assuming df_preprocessed is a DataFrame with the correct features
#     df = df_preprocessed.copy()
#     # Predict anomalies using the loaded model
#     if df.empty:
#         return jsonify({'error': 'No data to process'}), 400
#     if not isinstance(df, pd.DataFrame):
#         return jsonify({'error': 'Invalid data format'}), 400
#     # Ensure the DataFrame has the correct shape and features
#     if df.shape[1] < 2:  # Adjust based on your model's expected input
#         return jsonify({'error': 'Insufficient features in the DataFrame'}), 400
#     # Predict anomalies
#     try:
#         df = df.dropna()  # Drop rows with NaN values if necessary
#         if df.empty:
#             return jsonify({'error': 'No data after dropping NaN values'}), 400
#         df = df.select_dtypes(include=[np.number])  # Ensure only numeric data is used
#         if df.empty:
#             return jsonify({'error': 'No numeric data to process'}), 400
#         df = df.reset_index(drop=True)  # Reset index to avoid issues with model input
#         if df.shape[1] < 2:  # Ensure at least two features
#             return jsonify({'error': 'Insufficient features in the DataFrame'}), 400
#     except Exception as e:
#         return jsonify({'error': f'Error processing DataFrame: {str(e)}'}), 400
#     # Predict anomalies
#     try:
#         df = predict_anomalies(df)
#     except Exception as e:
#         return jsonify({'error': f'Error predicting anomalies: {str(e)}'}), 400
#     # Save to session or database as needed
#     df.to_csv('uploads/last_traffic.csv', index=False)
#     # return redirect('/traffic')

@cnn.route('/predict', methods=['POST'])
def predict():
    try:
        # Example: expecting JSON with 'data' key containing input features
        data = request.get_json(force=True)
        features = np.array(data['data']).reshape(1, -1)  # Adjust shape as needed

        # If your model expects images, reshape accordingly
        # features = features.reshape((1, height, width, channels))

        prediction = model.predict(features)
        predicted_class = np.argmax(prediction, axis=1)[0]

        return jsonify({'prediction': int(predicted_class)})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# No need to include app.run() here
# This file only defines routes and logic, similar to auth.py and view.py
@cnn.route('/api/traffic')
def api_traffic():
    try:
        df = pd.read_csv('uploads/last_traffic.csv')
        data = df.to_dict(orient='records')
        return jsonify(data)
    except Exception:
        return jsonify([])
    
@cnn.route('/upload_traffic', methods=['POST'])
def upload_traffic():
    if 'csv_file' not in request.files:
        return redirect('/')
    file = request.files['csv_file']
    if file.filename == '':
        return redirect('/')
    if file.content_length is not None and file.content_length > 30 * 1024 * 1024:
        return jsonify({'error': 'File too large. Max size is 30MB.'}), 400
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    df = pd.read_csv(filepath)
    df_processed = preprocess_csv(df)
    X = df_processed.values.astype('float32')
    X = X.reshape((-1, 64, 1))
    # Check model input shape
    print("Model expects input shape:", model.input_shape)

    # Check your data shape
    print("Your data shape:", X.shape)
    preds = model.predict(X)
    df['Attack'] = (preds > 0.5).astype(int)
    df.to_csv(os.path.join(UPLOAD_FOLDER, 'last_traffic.csv'), index=False)
    return redirect('/traffic')

@cnn.route('/traffic')
def traffic():
    try:
        df = pd.read_csv(os.path.join(UPLOAD_FOLDER, 'last_traffic.csv'))
        traffic = df.to_dict(orient='records')
    except Exception:
        traffic = []
    return render_template('traffic.html', traffic=traffic)

@cnn.route('/live_capture')
def live_capture():
    try:
        # Use live_results for live capture data
        traffic = live_results[-25:]  # Last 25 results
    except Exception:
        traffic = []
    return render_template('live_traffic.html', traffic=traffic)

@cnn.route('/api/live_traffic')
def api_live_traffic():
    if not live_results:
        return jsonify([])
    return jsonify(live_results[-25:])  # Last 25 results

@cnn.route('/api/attack_notification')
def attack_notification():
    try:
        # Use live_results for attack notification from live capture
        recent_results = live_results[-25:]  # Last 25 results
        attack_count = sum(1 for r in recent_results if r.get('Attack', 0))
        total = len(recent_results)
        has_attack = attack_count > 0
        return jsonify({
            'attack_detected': has_attack,
            'attack_count': attack_count,
            'total_records': total
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    
@cnn.route('/api/stop_capture_thread', methods=['POST'])
def stop_capture_thread():
    try:
        from website.livecapture import stop_capture_thread
        stop_capture_thread()
        return jsonify({'status': 'Capture thread stopped successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@cnn.route('/api/start_capture_thread', methods=['POST'])
def start_capture_thread_api():
    try:
        from website.livecapture import start_capture_thread
        data = request.get_json()
        interface = data.get('interface')  # Default to None
        if not interface:
            return jsonify({'error': 'No interface specified'}), 400
        start_capture_thread(interface)
        return jsonify({'status': 'Capture thread started successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500 
    
@cnn.route('/api/download_xls')
def download_xls():
    # Connect to MySQL
    conn = mysql.connector.connect(
        host='localhost',
        user='root',
        password='dandyj4s4t1rt4#',
        database='skripsi_final'
    )
    # Explicitly select columns except 'id' and 'proto_name'
    query = "SELECT real_timestamp, srcip_real, dstip_real, srcport_real, dstport_real, proto, rate, sttl, dload, swin, stcpb, dtcpb, trans_depth, response_body_len, ct_dst_ltm, ct_src_ltm, ct_src_dport_ltm, ct_src_dport_ltm, ct_dst_sport_ltm, is_ftp_login, Attack, Probability FROM live_capture"
    df = pd.read_sql(query, conn)
    conn.close()

    # Convert DataFrame to Excel in memory
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='LiveTraffic')
    output.seek(0)

    return send_file(
        output,
        download_name="live_traffic.xlsx",
        as_attachment=True,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    
@cnn.route('/api/metrics')
def get_metrics():
    return jsonify(metrics)

@cnn.route('/api/interfaces')
def api_interfaces():
    interfaces = get_available_interfaces()
    return jsonify(interfaces)