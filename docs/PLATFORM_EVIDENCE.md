# Platform Evidence

Only what was actually run is recorded here.

## Environment
- Architecture (`uname -m`): s390x
- Python version: 3.12.3
- Memory / storage: 7.8 GiB RAM (6.6 GiB available), no swap; 50 GB root disk, 3.0 GB used, 45 GB free
- Packages and versions: numpy 1.26.4, scikit-learn 1.4.1.post1, SciPy 1.11.4, matplotlib 3.6.3, pytest 7.4.4

## Model run on LinuxONE

- Status: DONE
- Architecture: s390x (`uname -m`)
- Python: 3.12.3
- Commit tested: 4be1798 (Sequence engine and fixtures)
- Test command: `python -m unittest discover -s tests`
- Result: Ran 28 tests, OK (exit code 0)
- Fixture metrics: TP=2 FP=0 TN=4 FN=0
- Library versions: numpy 1.26.4, scikit-learn 1.4.1.post1, SciPy 1.11.4, matplotlib 3.6.3, pytest 7.4.4
- Screenshots: results/platform_evidence/01_environment.png, results/platform_evidence/02_versions.png

## Constraints and fallbacks
- No fallbacks were needed. The tests ran directly on LinuxONE (s390x) in the project's `.venv`.