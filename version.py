# =============================================================================
# version.py - Single source of truth for Betta-Morpho version metadata
# =============================================================================
# Usage:
#   from version import __version__, __created__, __author__
#
# All Python scripts in this project import from here.
# To bump the version: change __version__ in this file only.
# Rust version is managed separately via rust-runtime/Cargo.toml.
#
# Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
# License : Apache-2.0 - see LICENSE
# Version : 2.4.0
# Created : 01.04.2026
# =============================================================================

__version__ = "2.4.0"
__created__ = "01.04.2026"
__author__ = "Vitalii Khomenko <khomenko.vitalii@pm.me>"
__license__ = "Apache-2.0"
