#!/usr/bin/env python3
import pyshark
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import ipaddress
import tensorflow as tf
from tensorflow.keras import layers, callbacks
import os
import json
import pickle
from datetime import datetime
import argparse

def process_pcap(file_path, label=None):
    """
    Process a PCAP file and extract features relevant to DDoS, DNS tunneling, and MitM attacks.
    
    Args:
        file_path: Path to the pcap file
        label: Optional label (0 for normal, 1 for malicious)
    
    Returns:
        DataFrame with extracted features
    """
    data = []
    print(f"Processing file: {file_path}")
    
    try:
        capture = pyshark.FileCapture(file_path, only_summaries=False)
        
        # Track DNS query/response patterns for tunneling detection
        dns_queries = {}
        packet_count = 0
        
        for packet in capture:
            packet_count += 1
            packet_data = {}
            
            if packet_count % 10000 == 0:
                print(f"Processed {packet_count} packets...")
            
            try:
                # Basic IP features
                if hasattr(packet, 'ip'):
                    packet_data['src_ip'] = packet.ip.src
                    packet_data['dst_ip'] = packet.ip.dst
                    packet_data['ip_len'] = int(packet.ip.len)
                    packet_data['ttl'] = int(packet.ip.ttl) if hasattr(packet.ip, 'ttl') else 0
                else:
                    continue
                
                # Protocol features
                packet_data['protocol'] = int(packet.ip.proto) if hasattr(packet.ip, 'proto') else 0
                
                # Layer 4 features
                if hasattr(packet, 'tcp'):
                    packet_data['src_port'] = int(packet.tcp.srcport)
                    packet_data['dst_port'] = int(packet.tcp.dstport)
                    packet_data['tcp_len'] = int(packet.tcp.len) if hasattr(packet.tcp, 'len') else 0
                    packet_data['tcp_flags'] = int(packet.tcp.flags, 16) if hasattr(packet.tcp, 'flags') else 0
                    packet_data['tcp_window_size'] = int(packet.tcp.window_size) if hasattr(packet.tcp, 'window_size') else 0
                elif hasattr(packet, 'udp'):
                    packet_data['src_port'] = int(packet.udp.srcport)
                    packet_data['dst_port'] = int(packet.udp.dstport)
                    packet_data['tcp_len'] = 0
                    packet_data['tcp_flags'] = 0
                    packet_data['tcp_window_size'] = 0
                else:
                    packet_data['src_port'] = 0
                    packet_data['dst_port'] = 0
                    packet_data['tcp_len'] = 0
                    packet_data['tcp_flags'] = 0
                    packet_data['tcp_window_size'] = 0
                
                # DNS-specific features (for DNS tunneling detection)
                if hasattr(packet, 'dns'):
                    packet_data['is_dns'] = 1
                    
                    # Extract DNS query data
                    if hasattr(packet.dns, 'qry_name'):
                        packet_data['dns_query_len'] = len(packet.dns.qry_name)
                        packet_data['dns_query_subdomain_count'] = packet.dns.qry_name.count('.')
                        
                        # Check for entropy (randomness) in DNS query (sign of tunneling)
                        import math
                        query = packet.dns.qry_name
                        entropy = 0
                        counter = {}
                        for c in query:
                            if c in counter:
                                counter[c] += 1
                            else:
                                counter[c] = 1
                        
                        for k in counter:
                            p = counter[k] / len(query)
                            entropy -= p * math.log2(p)
                        
                        packet_data['dns_query_entropy'] = entropy
                    else:
                        packet_data['dns_query_len'] = 0
                        packet_data['dns_query_subdomain_count'] = 0
                        packet_data['dns_query_entropy'] = 0
                else:
                    packet_data['is_dns'] = 0
                    packet_data['dns_query_len'] = 0
                    packet_data['dns_query_subdomain_count'] = 0
                    packet_data['dns_query_entropy'] = 0
                
                # ARP features (for MITM detection)
                if hasattr(packet, 'arp'):
                    packet_data['is_arp'] = 1
                    packet_data['arp_opcode'] = int(packet.arp.opcode) if hasattr(packet.arp, 'opcode') else 0
                else:
                    packet_data['is_arp'] = 0
                    packet_data['arp_opcode'] = 0
                
                # Add label if provided
                if label is not None:
                    packet_data['label'] = label
                
                data.append(packet_data)
                
            except AttributeError as e:
                # Skip packets that don't have the required attributes
                continue
            except Exception as e:
                print(f"Error processing packet: {e}")
                continue
                
    except Exception as e:
        print(f"Error processing file {file_path}: {e}")
    finally:
        capture.close()
    
    df = pd.DataFrame(data)
    
    # Add some derived features useful for attack detection
    if not df.empty:
        # Add timestamp information
        df['timestamp'] = range(len(df))
        
        # Compute aggregate features over time windows
        window_size = min(1000, len(df))
        df['packet_rate'] = df['timestamp'].rolling(window=window_size).count().fillna(0)
        
        # Flag potential SYN flood (common DDoS technique)
        if 'tcp_flags' in df.columns:
            # SYN flag (bit 1) is set but ACK flag (bit 4) is not
            df['is_syn_flood'] = ((df['tcp_flags'] & 0x02) > 0) & ((df['tcp_flags'] & 0x10) == 0)
            df['syn_flood_rate'] = df['is_syn_flood'].rolling(window=window_size).sum().fillna(0)
        else:
            df['is_syn_flood'] = 0
            df['syn_flood_rate'] = 0
    
    if not df.empty:
        print(f"Extracted {len(df)} packet records with {len(df.columns)} features")
        print("Features:", df.columns.tolist())
    else:
        print("No valid packets extracted from the pcap file.")
    
    return df

def preprocess_data(df, scaler=None):
    """
    Preprocess the data for model training or prediction.
    
    Args:
        df: DataFrame with extracted features
        scaler: Optional pre-fitted StandardScaler
    
    Returns:
        X: Scaled features
        y: Labels (if available)
        scaler: Fitted StandardScaler
    """
    if df.empty:
        print("No data to preprocess.")
        return None, None, scaler
    
    # Ensure all required columns exist and handle missing values
    required_columns = [
        'src_ip', 'dst_ip', 'ip_len', 'ttl', 'protocol',
        'src_port', 'dst_port', 'tcp_len', 'tcp_flags', 'tcp_window_size',
        'is_dns', 'dns_query_len', 'dns_query_subdomain_count', 'dns_query_entropy',
        'is_arp', 'arp_opcode', 'packet_rate', 'is_syn_flood', 'syn_flood_rate'
    ]
    
    for col in required_columns:
        if col not in df.columns:
            df[col] = 0
    
    # Convert IP addresses to integers for machine learning
    df['src_ip_int'] = df['src_ip'].apply(lambda ip: int(ipaddress.IPv4Address(ip)))
    df['dst_ip_int'] = df['dst_ip'].apply(lambda ip: int(ipaddress.IPv4Address(ip)))
    
    # Prepare feature matrix
    feature_columns = [
        'src_ip_int', 'dst_ip_int', 'ip_len', 'ttl', 'protocol',
        'src_port', 'dst_port', 'tcp_len', 'tcp_flags', 'tcp_window_size',
        'is_dns', 'dns_query_len', 'dns_query_subdomain_count', 'dns_query_entropy',
        'is_arp', 'arp_opcode', 'packet_rate', 'is_syn_flood', 'syn_flood_rate'
    ]
    
    X = df[feature_columns]
    
    # Extract labels if available
    y = df['label'] if 'label' in df.columns else None
    
    # Scale features
    if scaler is None:
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
    else:
        X_scaled = scaler.transform(X)
    
    return X_scaled, y, scaler

def build_model(input_shape):
    """
    Build a neural network model for attack detection.
    """
    model = tf.keras.Sequential([
        layers.Dense(128, activation='relu', input_shape=(input_shape,)),
        layers.BatchNormalization(),
        layers.Dropout(0.3),
        layers.Dense(64, activation='relu'),
        layers.BatchNormalization(),
        layers.Dropout(0.2),
        layers.Dense(32, activation='relu'),
        layers.Dense(1, activation='sigmoid')
    ])
    
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
        loss='binary_crossentropy',
        metrics=['accuracy', tf.keras.metrics.Precision(), tf.keras.metrics.Recall()]
    )
    
    return model

def train_model(normal_pcap, attack_pcap, model_path='network_attack_model', scaler_path='network_attack_scaler.pkl'):
    """
    Train a model using labeled normal and attack traffic.
    
    Args:
        normal_pcap: PCAP file with normal traffic
        attack_pcap: PCAP file with attack traffic
        model_path: Path to save the trained model
        scaler_path: Path to save the fitted scaler
    """
    print(f"Processing normal traffic from {normal_pcap}...")
    normal_df = process_pcap(normal_pcap, label=0)
    
    print(f"Processing attack traffic from {attack_pcap}...")
    attack_df = process_pcap(attack_pcap, label=1)
    
    # Combine datasets
    if normal_df.empty or attack_df.empty:
        print("Error: One or both datasets are empty. Cannot train model.")
        return
    
    df = pd.concat([normal_df, attack_df], ignore_index=True)
    print(f"Combined dataset: {len(df)} packets, {df['label'].sum()} labeled as attacks")
    
    # Preprocess data
    X, y, scaler = preprocess_data(df)
    
    # Split into training and validation sets
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Build and train model
    input_shape = X_train.shape[1]
    model = build_model(input_shape)
    
    early_stopping = callbacks.EarlyStopping(
        monitor='val_loss', 
        patience=5,
        restore_best_weights=True
    )
    
    print("Training model...")
    history = model.fit(
        X_train, y_train,
        validation_data=(X_val, y_val),
        epochs=30,
        batch_size=64,
        callbacks=[early_stopping]
    )
    
    # Evaluate model
    print("Evaluating model...")
    loss, accuracy, precision, recall = model.evaluate(X_val, y_val)
    print(f"Validation Loss: {loss:.4f}")
    print(f"Validation Accuracy: {accuracy:.4f}")
    print(f"Validation Precision: {precision:.4f}")
    print(f"Validation Recall: {recall:.4f}")
    
    # Generate predictions for validation set
    y_pred = (model.predict(X_val) > 0.5).astype(int)
    print("Classification Report:")
    print(classification_report(y_val, y_pred))
    print("Confusion Matrix:")
    print(confusion_matrix(y_val, y_pred))
    
    # Save model and scaler
    print(f"Saving model to {model_path}...")
    model.save(model_path)
    
    print(f"Saving scaler to {scaler_path}...")
    with open(scaler_path, 'wb') as f:
        pickle.dump(scaler, f)
    
    print("Training completed successfully.")

def train_model_one_pcap(pcap_file, model_path='network_attack_model', scaler_path='network_attack_scaler.pkl'):
    """
    Train a model using a single PCAP file that contains both labeled normal and attack traffic.
    
    Args:
        pcap_file: PCAP file with mixed traffic (must have 'label' column in the processed data)
        model_path: Path to save the trained model
        scaler_path: Path to save the fitted scaler
    """
    print(f"Processing mixed traffic from {pcap_file}...")
    df = process_pcap(pcap_file)
    
    if df.empty:
        print("Error: Dataset is empty. Cannot train model.")
        return
    
    if 'label' not in df.columns:
        print("Error: No 'label' column found in the dataset. Please ensure your PCAP has labeled traffic.")
        return
    
    print(f"Dataset: {len(df)} packets, {df['label'].sum()} labeled as attacks")
    
    # Preprocess data
    X, y, scaler = preprocess_data(df)
    
    # Split into training and validation sets
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Build and train model
    input_shape = X_train.shape[1]
    model = build_model(input_shape)
    
    early_stopping = callbacks.EarlyStopping(
        monitor='val_loss', 
        patience=5,
        restore_best_weights=True
    )
    
    print("Training model...")
    history = model.fit(
        X_train, y_train,
        validation_data=(X_val, y_val),
        epochs=30,
        batch_size=64,
        callbacks=[early_stopping]
    )
    
    # Evaluate model
    print("Evaluating model...")
    loss, accuracy, precision, recall = model.evaluate(X_val, y_val)
    print(f"Validation Loss: {loss:.4f}")
    print(f"Validation Accuracy: {accuracy:.4f}")
    print(f"Validation Precision: {precision:.4f}")
    print(f"Validation Recall: {recall:.4f}")
    
    # Generate predictions for validation set
    y_pred = (model.predict(X_val) > 0.5).astype(int)
    print("Classification Report:")
    print(classification_report(y_val, y_pred))
    print("Confusion Matrix:")
    print(confusion_matrix(y_val, y_pred))
    
    # Save model and scaler
    print(f"Saving model to {model_path}...")
    model.save(model_path)
    
    print(f"Saving scaler to {scaler_path}...")
    with open(scaler_path, 'wb') as f:
        pickle.dump(scaler, f)
    
    print("Training completed successfully.")

def detect_attacks(pcap_file, model_path='network_attack_model', scaler_path='network_attack_scaler.pkl', output_dir='./'):
    """
    Detect attacks in a PCAP file using a trained model.
    
    Args:
        pcap_file: PCAP file to analyze
        model_path: Path to the trained model
        scaler_path: Path to the fitted scaler
        output_dir: Directory to save results
    """
    print(f"Loading model from {model_path}...")
    model = tf.keras.models.load_model(model_path)
    
    print(f"Loading scaler from {scaler_path}...")
    with open(scaler_path, 'rb') as f:
        scaler = pickle.load(f)
    
    print(f"Processing traffic from {pcap_file}...")
    df = process_pcap(pcap_file)
    
    if df.empty:
        print("Error: No valid packets found in the PCAP file.")
        return
    
    # Save original IPs for reference
    src_ips = df['src_ip'].copy()
    dst_ips = df['dst_ip'].copy()
    
    # Preprocess data
    X, _, _ = preprocess_data(df, scaler)
    
    # Make predictions
    print("Detecting attacks...")
    predictions = model.predict(X)
    attack_scores = predictions.flatten()
    
    # Add predictions to dataframe
    df['attack_score'] = attack_scores
    df['attack_detected'] = (attack_scores > 0.5).astype(int)
    
    # Restore original IPs
    df['src_ip'] = src_ips
    df['dst_ip'] = dst_ips
    
    # Analyze attack types
    attack_packets = df[df['attack_detected'] == 1]
    
    if len(attack_packets) > 0:
        print(f"Detected {len(attack_packets)} attack packets out of {len(df)} total packets")
        
        # Identify potential attack types
        ddos_indicators = attack_packets['is_syn_flood'].sum() > 0 or attack_packets['syn_flood_rate'].max() > 10
        dns_tunnel_indicators = (attack_packets['is_dns'] == 1) & (attack_packets['dns_query_entropy'] > 4)
        mitm_indicators = (attack_packets['is_arp'] == 1) & (attack_packets['arp_opcode'] == 2)
        
        print("\nAttack Type Analysis:")
        if ddos_indicators:
            print("- DDoS attack indicators detected (SYN flooding or high packet rates)")
        if dns_tunnel_indicators.any():
            print("- DNS tunneling indicators detected (high entropy DNS queries)")
        if mitm_indicators.any():
            print("- Man-in-the-Middle attack indicators detected (suspicious ARP replies)")
        
        # Identify top source IPs involved in attacks
        attack_sources = attack_packets['src_ip'].value_counts().head(10)
        print("\nTop Attack Sources:")
        for ip, count in attack_sources.items():
            print(f"- {ip}: {count} packets")
    else:
        print("No attack packets detected.")
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_file = os.path.join(output_dir, f"attack_detection_{timestamp}.csv")
    os.makedirs(output_dir, exist_ok=True)
    
    df.to_csv(results_file, index=False)
    print(f"Results saved to {results_file}")
    
    # Generate summary report
    summary_file = os.path.join(output_dir, f"attack_summary_{timestamp}.txt")
    with open(summary_file, 'w') as f:
        f.write(f"Attack Detection Summary for {pcap_file}\n")
        f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"Total packets analyzed: {len(df)}\n")
        f.write(f"Attack packets detected: {len(attack_packets)} ({len(attack_packets)/len(df)*100:.2f}%)\n\n")
        
        f.write("Attack Type Analysis:\n")
        if ddos_indicators:
            f.write("- DDoS attack indicators detected (SYN flooding or high packet rates)\n")
        if dns_tunnel_indicators.any():
            f.write("- DNS tunneling indicators detected (high entropy DNS queries)\n")
        if mitm_indicators.any():
            f.write("- Man-in-the-Middle attack indicators detected (suspicious ARP replies)\n")
        
        f.write("\nTop Attack Sources:\n")
        for ip, count in attack_sources.items():
            f.write(f"- {ip}: {count} packets\n")
    
    print(f"Summary report saved to {summary_file}")

def parse_arguments():
    """
    Parse command line arguments.
    """
    parser = argparse.ArgumentParser(description='Network Attack Detection')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Train command with separate normal and attack pcaps
    train_parser = subparsers.add_parser('train', help='Train model with separate normal and attack pcaps')
    train_parser.add_argument('--normal', required=True, help='PCAP file with normal traffic')
    train_parser.add_argument('--attack', required=True, help='PCAP file with attack traffic')
    train_parser.add_argument('--model', default='network_attack_model', help='Path to save the model')
    train_parser.add_argument('--scaler', default='network_attack_scaler.pkl', help='Path to save the scaler')
    
    # Train with a single labeled pcap
    train_one_parser = subparsers.add_parser('train_one', help='Train model with a single labeled PCAP')
    train_one_parser.add_argument('--pcap', required=True, help='PCAP file with labeled traffic')
    train_one_parser.add_argument('--model', default='network_attack_model', help='Path to save the model')
    train_one_parser.add_argument('--scaler', default='network_attack_scaler.pkl', help='Path to save the scaler')
    
    # Detect command
    detect_parser = subparsers.add_parser('detect', help='Detect attacks in a PCAP file')
    detect_parser.add_argument('--pcap', required=True, help='PCAP file to analyze')
    detect_parser.add_argument('--model', default='network_attack_model', help='Path to the trained model')
    detect_parser.add_argument('--scaler', default='network_attack_scaler.pkl', help='Path to the fitted scaler')
    detect_parser.add_argument('--output', default='./', help='Directory to save results')
    
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    
    if args.command == 'train':
        train_model(args.normal, args.attack, args.model, args.scaler)
    elif args.command == 'train_one':
        train_model_one_pcap(args.pcap, args.model, args.scaler)
    elif args.command == 'detect':
        detect_attacks(args.pcap, args.model, args.scaler, args.output)
    else:
        print("No command specified. Use --help for usage information.")
