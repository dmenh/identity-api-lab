"""Idempotent schema and demonstration-data bootstrap."""
import argparse
from .main import Base, engine, seed

parser=argparse.ArgumentParser()
parser.add_argument('command',choices=['migrate','seed'])
args=parser.parse_args()
if args.command=='migrate': Base.metadata.create_all(engine)
else: seed()
print(args.command+' completed')
