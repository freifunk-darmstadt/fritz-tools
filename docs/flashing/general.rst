General information
===================

Selecting the right Image
-------------------------

Gluon builds by default factory and sysupgrade images. AVM devices don't need special factory-images, so most of them are flashed via the sysupgrade images.

.. Note:: In case your community uses a tool for providing firmware, factory-images are often referenced as "First-installation-images" and sysupgrade-images are often called "update-" or "upgrade-images".

Exceptions apply for the FRITZ!Box 4040. This device needs a special bootloader-image for use with the flash-script. Flashing with a sysupgrade image won't work.

Windows compatibility
---------------------

As Windows compatibility is not yet tested nor documented, the currently recommended way is using a live-version of Ubuntu.
