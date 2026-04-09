FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY globalping_monitor.py .
COPY gp_check.py .
COPY run_check.py .
COPY validate_odontoprev.py .
COPY report_pdf.py .

# Volume para salvar JSON e PDF gerados
VOLUME ["/app/output"]

ENTRYPOINT ["python", "gp_check.py"]
CMD ["--help"]
