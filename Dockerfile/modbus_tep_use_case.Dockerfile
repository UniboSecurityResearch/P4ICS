# Base con CUDA 11.8 + cuDNN 8 (runtime) – adatta ad A100
FROM nvidia/cuda:11.8.0-cudnn8-runtime-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Python 3 + strumenti
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.10 python3.10-distutils python3-pip python3-dev \
    build-essential gcc g++ make wget curl git gfortran \
    libatlas-base-dev liblapack-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Alias python/pip -> python3.10/pip3
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.10 1 && \
    update-alternatives --install /usr/bin/pip pip /usr/bin/pip3 1

# Aggiorna pip/setuptools/wheel
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# TensorFlow GPU compatibile con CUDA 11.8
# Nota: TF 2.12 richiede protobuf >=3.20; manteniamo il tuo vincolo "<5"
RUN pip install --no-cache-dir \
    "tensorflow==2.12.*" "protobuf>=3.20.3,<5"

# Pacchetti Python (pin scelti per compatibilità con TF2.12 + Py3.10)
# Ho tenuto quanto possibile dai tuoi requirements; alcuni devono essere aggiornati.
RUN pip install --no-cache-dir \
    h5py==3.8.0 \
    jupyter==1.0.0 \
    lime==0.2.0.1 \
    networkx==2.8.8 \
    numpy==1.23.5 \
    pandas==1.5.3 \
    pandocfilters==1.5.0 \
    pytz==2023.3 \
    scikit-learn==1.2.2 \
    scipy==1.10.1 \
    seaborn==0.12.2 \
    shap==0.41.0 \
    six==1.16.0