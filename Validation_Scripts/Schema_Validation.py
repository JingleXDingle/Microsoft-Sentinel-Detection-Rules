#This script validates that every YAML and JSON file containing Microsoft Sentinel detection rules adheres to the defined schema.
import os
import sys
import json
import yaml
import logging
import argparse
import re
from jsonschema import Draft7Validator
