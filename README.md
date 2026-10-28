# Phishing URL Detector

An AI-powered phishing URL detection web application built with Flask and Google Safe Browsing API. The application analyzes URLs to help identify potential phishing threats through machine learning and URL safety checks.

## Overview

Phishing attacks use deceptive websites and URLs to trick users into revealing sensitive information. This project aims to make URL safety checking more accessible through a web interface that combines machine learning-based detection with Google Safe Browsing checks.

## Features

- **AI-Based Detection:** Uses a trained machine learning model to classify URLs.
- **Google Safe Browsing Integration:** Checks URLs against Google's web safety service.
- **Web Interface:** Provides a user-friendly interface for submitting URLs for analysis.
- **Detection Logs:** Maintains logs of URL checking activity.
- **Model Training:** Includes a Python script for training the phishing detection model.

## Tech Stack

- **Programming Language:** Python
- **Backend Framework:** Flask
- **Machine Learning:** Trained model saved using Pickle
- **Security API:** Google Safe Browsing API
- **Frontend:** HTML and CSS
- **Tools:** Git and GitHub

## Project Structure

```text
phishing-detector/
├── app.py
├── train_model.py
├── phishing_model.pkl
├── logs.txt
├── welcome.html
└── templates/
```

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/samgoel15/phishing-detector.git
cd phishing-detector
```

### 2. Set Up a Virtual Environment (Recommended)

```bash
python -m venv venv
```

Activate the environment:

**Windows**
```bash
venv\Scripts\activate
```

**macOS/Linux**
```bash
source venv/bin/activate
```

### 3. Install Dependencies

Install Flask and the other Python packages required by the application.

```bash
pip install flask requests scikit-learn numpy pandas
```

If the project uses additional libraries, install those as well. You can create a `requirements.txt` file to record the dependencies.

### 4. Configure Google Safe Browsing API

Obtain an API key through the Google Cloud Console and enable the Google Safe Browsing API if required for your configuration.

Configure the key using the method and variable expected by `app.py`. Avoid hardcoding API keys or uploading secrets to GitHub.

### 5. Run the Application

```bash
python app.py
```

Open the local address displayed in the terminal, commonly `http://127.0.0.1:5000`, in your browser.

## Machine Learning Model

The repository includes `train_model.py` for model training and `phishing_model.pkl` for the saved trained model. The application can use the saved model for predictions, provided the model and input features are compatible.

## Future Improvements

- Deploy the application to a hosting platform.
- Improve detection through additional URL features and training data.
- Add automated tests and error handling.
- Improve reporting of detection results and potential threats.

## Disclaimer

This project is intended for educational and research purposes. Detection results are not a guarantee that a URL is safe or malicious. Always exercise caution when visiting unfamiliar websites.

## Author

**Soumya Goel**

GitHub: [@samgoel15](https://github.com/samgoel15)

---

If you find this project useful, consider giving the repository a star!
