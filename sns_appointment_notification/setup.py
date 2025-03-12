from setuptools import setup, find_packages

setup(
    name="sns_appointment_notification",
    version="0.1.1",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "boto3>=1.26.0"
    ],
    python_requires=">=3.8",
)