from setuptools import setup, find_packages

setup(
    name="sasu-blockchain",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "pycryptodome",
        "flask"
    ],
    entry_points={
        "console_scripts": [
            "sasu-create-wallet=scripts.create_wallet:main",
            "sasu-mine-block=scripts.mine_block:main"
        ]
    }
)
