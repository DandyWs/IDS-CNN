# Network Intrusion Detection System

This project implements a Network Intrusion Detection System (NIDS) using a Convolutional Neural Network (CNN) for anomaly detection in network traffic. The system is designed to monitor real-time traffic data and identify potential intrusions based on learned patterns from historical data.

## Project Structure

- **templates/**: Contains HTML templates for the web application.
  - **base.html**: The base template that includes common HTML structure.
  - **traffic.html**: Displays real-time traffic data and alerts for detected anomalies.

- **static/**: Directory for static files such as CSS, JavaScript, and images.

- **app.py**: The main application file that runs the web server. It includes routes for serving HTML templates and handling API requests for traffic data. This file also implements the CNN model for anomaly detection.

- **README.md**: Documentation for the project, including setup instructions, features, and usage guidelines.

## Features

- Real-time traffic monitoring: The application fetches and displays network traffic data every two seconds.
- Anomaly detection: Utilizes a trained CNN model to identify anomalies in network traffic.
- Alerts for detected anomalies: The system provides notifications in the user interface when potential intrusions are detected.

## Setup Instructions

1. Clone the repository to your local machine.
2. Install the required dependencies. You may need to create a virtual environment and run:
   ```
   pip install -r requirements.txt
   ```
3. Train the CNN model on historical traffic data and save the model.
4. Update the `app.py` file to load the trained model and implement the API endpoint for traffic data processing.
5. Run the application:
   ```
   python app.py
   ```
6. Open your web browser and navigate to `http://localhost:5000` to access the application.

## Usage

- The traffic data will be displayed in a table format on the `traffic.html` page.
- Anomalies detected by the CNN model will trigger alerts, which will be displayed on the same page.

## Future Enhancements

- Improve the CNN model's accuracy by using more diverse training data.
- Implement user authentication for accessing the application.
- Add logging and monitoring features for better insights into network traffic patterns.