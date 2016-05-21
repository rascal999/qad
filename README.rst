QAD
=======================

QAD is a quick and dirty web application scanner to pick up on low hanging
fruit which may be beneficial to clients if mentioned in a pentest report.

QAD is not multi-threaded and tries to be minimalist in output. It will
process response headers, enumerate a small list of common (and potentially
interesting) directories, and will advise if login or registration forms are
available over a HTTP connection.
