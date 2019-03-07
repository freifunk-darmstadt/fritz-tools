import unittest

from fritzflash import determine_image_name


class TestFritzflash(unittest.TestCase):
    def test_image_names(self):
        # FRITZ!Box 4020
        images_4020 = determine_image_name("219")
        self.assertIn("avm-fritz-box-4020-sysupgrade.bin", images_4020)
        self.assertIn("fritz4020-squashfs-sysupgrade.bin", images_4020)
        self.assertIn("avm_fritz4020-squashfs-sysupgrade.bin", images_4020)

        # FRITZ!Box 4040
        images_4040 = determine_image_name("227")
        self.assertIn("avm-fritz-box-4040-bootloader.bin", images_4040)
        self.assertIn("avm_fritzbox-4040-squashfs-eva.bin", images_4040)
        self.assertNotIn("avm_fritzbox-4040-initramfs-fit-uImage.itb", images_4040)
        self.assertNotIn("avm_fritzbox-4040-squashfs-sysupgrade.bin", images_4040)

        # FRITZ!WLAN Repeater 300E
        images_300e = determine_image_name("173")
        self.assertIn("avm-fritz-wlan-repeater-300e-sysupgrade.bin", images_300e)
        self.assertIn("fritz300e-squashfs-sysupgrade.bin", images_300e)

        # FRITZ!WLAN Repeater 450E
        images_450e = determine_image_name("200")
        self.assertIn("avm-fritz-wlan-repeater-450e-sysupgrade.bin", images_450e)
        self.assertIn("fritz450e-squashfs-sysupgrade.bin", images_450e)
