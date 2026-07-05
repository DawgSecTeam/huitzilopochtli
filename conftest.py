"""Root pytest conftest: put the repo root on sys.path so `import agent`,
`import common`, `import engine`, `import authoring` work the same way they
do for every script run throughout this project (no src-layout/installed
package is used).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
