import asyncio
import pyshark
import pandas as pd
import numpy as np
import threading
import joblib
import os
import csv
from flask import Blueprint, jsonify
from preprocessing.preprocess import preprocess_csv
from keras.models import load_model
import struct
import socket
import mysql.connector
from sklearn.metrics import precision_score, recall_score, f1_score

MODEL_PATH = 'model/CNNUpdate.h5'
model = load_model(MODEL_PATH)

live_results = []

capture_thread = None
capture_running = False

y_true = []
y_pred = []

metrics = {"precision": 0, "recall": 0, "f1": 0}


def ip_to_int(ip):
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except Exception:
        return 0
def packet_to_features(pkt):
    features = {}
    try:
        # For display only (not used in model)
        features['srcip_real'] = getattr(pkt.ip, 'src', '') if hasattr(pkt, 'ip') else ''
        # Get source port from TCP or UDP layer if available
        if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'srcport'):
            features['srcport_real'] = pkt.tcp.srcport
        elif hasattr(pkt, 'udp') and hasattr(pkt.udp, 'srcport'):
            features['srcport_real'] = pkt.udp.srcport
        else:
            features['srcport_real'] = ''
            
        # Get destination port from TCP or UDP layer if available
        if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'dstport'):
            try:
                features['dstport_real'] = int(pkt.tcp.dstport)
            except Exception:
                features['dstport_real'] = 0
        elif hasattr(pkt, 'udp') and hasattr(pkt.udp, 'dstport'):
            try:
                features['dstport_real'] = int(pkt.udp.dstport)
            except Exception:
                features['dstport_real'] = 0
        else:
            features['dstport_real'] = 0
        features['dstip_real'] = getattr(pkt.ip, 'dst', '') if hasattr(pkt, 'ip') else ''
        # Get real_timestamp for display only, with milliseconds
        if hasattr(pkt, 'sniff_time') and pkt.sniff_time is not None:
            features['real_timestamp_display'] = pkt.sniff_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-1]
        else:
            features['real_timestamp_display'] = None
        features['real_timestamp'] = pkt.sniff_time if hasattr(pkt, 'sniff_time') and pkt.sniff_time is not None else None

        # Model features (match your training order)
        # 1. proto
        proto = pkt.transport_layer if hasattr(pkt, 'transport_layer') else pkt.highest_layer
        features['proto'] = str(proto).strip().lower()

        # 2. rate (not available, set to 0)
        features['rate'] = 0

        # 3. sttl
        ip_layer = getattr(pkt, 'ip', None)
        features['sttl'] = int(ip_layer.ttl) if ip_layer and hasattr(ip_layer, 'ttl') else 0

        # 4. dload (not available, set to 0) NO
        features['dload'] = 0

        # 5. swin
        tcp_layer = getattr(pkt, 'tcp', None)
        features['swin'] = int(tcp_layer.window_size_value) if tcp_layer and hasattr(tcp_layer, 'window_size_value') else 0

        # 6. stcpb
        features['stcpb'] = int(tcp_layer.seq) if tcp_layer and hasattr(tcp_layer, 'seq') else 0

        # 7. dtcpb
        features['dtcpb'] = int(tcp_layer.ack) if tcp_layer and hasattr(tcp_layer, 'ack') else 0

        # 8. trans_depth (HTTP)
        features['trans_depth'] = 1 if hasattr(pkt, 'http') and hasattr(pkt.http, 'request_method') else 0

        # 9. response_body_len (HTTP)
        features['response_body_len'] = int(pkt.http.content_length) if hasattr(pkt, 'http') and hasattr(pkt.http, 'content_length') else 0

        # 10. ct_dst_ltm (not available, set to 0)
        features['ct_dst_ltm'] = 0

        # 11. ct_src_dport_ltm (not available, set to 0)
        features['ct_src_dport_ltm'] = 0

        # 12. ct_dst_sport_ltm (not available, set to 0)
        features['ct_dst_sport_ltm'] = 0

        # 13. ct_dst_src_ltm (not available, set to 0)
        features['ct_dst_src_ltm'] = 0

        # 14. is_ftp_login
        features['is_ftp_login'] = 1 if hasattr(pkt, 'ftp') and hasattr(pkt.ftp, 'request_command') and pkt.ftp.request_command == 'USER' else 0

        # 15. ct_src_ltm (not available, set to 0)
        features['ct_src_ltm'] = 0

        return features
    except Exception as e:
        print(f"Error processing packet: {e}")
        # Return all zeros for model features, keep empty for display fields
        return {k: 0 for k in [
            'proto', 'rate', 'sttl', 'dload', 'swin', 'stcpb', 'dtcpb',
            'trans_depth', 'response_body_len', 'ct_dst_ltm', 'ct_src_dport_ltm',
            'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'is_ftp_login', 'ct_src_ltm'
        ]}

def log_anomaly_to_csv(features_dict, filename='anomaly_log.csv'):
    # If file does not exist, write header first
    write_header = not os.path.exists(filename)
    with open(filename, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=features_dict.keys())
        if write_header:
            writer.writeheader()
        writer.writerow(features_dict)
        
def live_capture(interface):
    global capture_running
    capture_running = True
    scaler = joblib.load('model/scaler.save')
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    capture = pyshark.LiveCapture(interface=interface)
    print(f"Started live capture on {interface}")
    
    for pkt in capture.sniff_continuously():
        if not capture_running:
            print("Capture stopped.")
            break
        try:
            features_dict = packet_to_features(pkt)
            model_features = [
                'proto', 'rate', 'sttl', 'dload', 'swin', 'stcpb', 'dtcpb',
                'trans_depth', 'response_body_len', 'ct_dst_ltm', 'ct_src_dport_ltm',
                'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'is_ftp_login', 'ct_src_ltm'
            ]
            # For model prediction, use only model_features
            df = pd.DataFrame([{k: features_dict.get(k, 0) for k in model_features}])
            
            proto_encoder = joblib.load('model/proto_encoder.save')
            valid_proto = df['proto'].isin(proto_encoder.classes_)
            df = df[valid_proto]
            if df.empty:
                print("-")
                continue
            df['proto'] = proto_encoder.transform(df['proto'])
            
            # Preprocess the DataFrame  
            df_processed = preprocess_csv(df)
            print("Raw features:\n", df)
            print("Processed features:\n", df_processed)
            X_live = scaler.transform(df_processed)
            print("Scaled features:\n", X_live.reshape(15,))
            X_live = X_live.reshape((1, 15, 1))
            pred = model.predict(X_live)
            probabilities = float(pred[0][0])
            attack = int(probabilities > 0.3)
            # For display, keep all features
            df['proto_name'] = proto_encoder.inverse_transform(df['proto'])
            features_dict['Attack'] = attack
            features_dict['Probability'] = probabilities
            features_dict['proto_name'] = df['proto_name'].iloc[0]  # Use the string name for display
            
            features_dict['true_label'] = get_true_label_from_db(features_dict)  # Assuming true label is same as predicted for live capture
            # Placeholder for true label
            y_pred.append(attack)
            y_true.append(features_dict['true_label'])  # Replace 0 with actual label if available

            if len(y_true) > 0 and len(y_true) % 25 == 0:
                precision = precision_score(y_true, y_pred, zero_division=0)
                recall = recall_score(y_true, y_pred, zero_division=0)
                f1 = f1_score(y_true, y_pred, zero_division=0)
                print(f"Precision: {precision:.3f}, Recall: {recall:.3f}, F1-score: {f1:.3f}")
                metrics["precision"] = round(precision, 3)
                metrics["recall"] = round(recall, 3)
                metrics["f1"] = round(f1, 3)

            print("Features:", features_dict)
            live_results.append(features_dict)
            if features_dict['Attack'] == 1:
                log_anomaly_to_csv(features_dict, filename='model/anomaly_log.csv')
            insert_to_db(features_dict)  # Insert into MySQL
            if len(live_results) > 1000:
                live_results.pop(0)
        except Exception as e:
            print("Error in live capture:", e)
            import traceback
            traceback.print_exc()

# def start_capture_thread():
#     t = threading.Thread(target=live_capture, daemon=True)
#     t.start()
def get_available_interfaces():
    try:
        import pyshark
        # Try pyshark's get_interface_list() if available
        if hasattr(pyshark.LiveCapture, "get_interface_list"):
            interfaces = pyshark.LiveCapture.get_interface_list()
        else:
            # Fallback to psutil if pyshark doesn't have get_interface_list
            import psutil
            interfaces = list(psutil.net_if_addrs().keys())
        return interfaces
    except Exception as e:
        print("Error getting available interfaces:", e)
        return []
    
def start_capture_thread(interface):
    global capture_thread, capture_running
    if capture_thread is None or not capture_thread.is_alive():
        print(f"Starting live capture on interface: {interface}")
        capture_thread = threading.Thread(target=live_capture, args=(interface,), daemon=True)
        capture_thread.start()
    else:
        print("Capture thread already running.")
    
def insert_to_db(features):
    try:
        conn = mysql.connector.connect(
            host='localhost',
            user='root',
            password='dandyj4s4t1rt4#',
            database='skripsi_final'
        )
        cursor = conn.cursor()
        # Insert the data into the database
        sql = """INSERT INTO live_capture (srcip_real, srcport_real, dstip_real, dstport_real, real_timestamp, proto, rate, sttl, dload, swin, stcpb, dtcpb, trans_depth, response_body_len, ct_dst_ltm, ct_src_dport_ltm, ct_dst_sport_ltm, ct_dst_src_ltm, is_ftp_login, ct_src_ltm, Attack, Probability, proto_name)
                 VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        cursor.execute(sql, (
            features['srcip_real'], 
            features['srcport_real'], 
            features['dstip_real'], 
            features['dstport_real'], 
            features['real_timestamp'], 
            features['proto'], 
            features['rate'], 
            features['sttl'], 
            features['dload'], 
            features['swin'], 
            features['stcpb'], 
            features['dtcpb'], 
            features['trans_depth'], 
            features['response_body_len'], 
            features['ct_dst_ltm'], 
            features['ct_src_dport_ltm'], 
            features['ct_dst_sport_ltm'], 
            features['ct_dst_src_ltm'], 
            features['is_ftp_login'], 
            features['ct_src_ltm'],
            features['Attack'],
            features['Probability'],
            features['proto_name']))
        conn.commit()
        cursor.close()
        print("Data inserted successfully into MySQL")
    except mysql.connector.Error as e:
        print("Error inserting data into MySQL:", e)
    finally:
        if conn:
            conn.close()
            
def stop_capture_thread():
    global capture_running
    print("Stopping live capture thread...")
    capture_running = False

def get_true_label_from_db(features_dict):
    try:
        conn = mysql.connector.connect(
            host='localhost',
            user='root',
            password='dandyj4s4t1rt4#',
            database='skripsi_final'
        )
        cursor = conn.cursor()
        # Match by timestamp and IPs (adjust as needed for your schema)
        sql = """SELECT Attack FROM live_capture
                 WHERE real_timestamp = %s AND srcip_real = %s AND dstip_real = %s AND srcport_real = %s AND dstport_real = %s
                 ORDER BY id DESC LIMIT 1"""
        cursor.execute(sql, (
            features_dict['real_timestamp'],
            features_dict['srcip_real'],
            features_dict['dstip_real'],
            features_dict['srcport_real'],
            features_dict['dstport_real']
        ))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        if result:
            return int(result[0])
        else:
            return 0  # Default to normal if not found
    except Exception as e:
        print("Error fetching true label from DB:", e)
        return 0

