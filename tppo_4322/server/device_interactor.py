"""This is device state monitor. It watches for device emulator file changes and sets a callback when changes occur."""

import pyinotify
import asyncio
import logging
import json

from constants import DEVICE_PATH

logger = logging.getLogger(__name__)


def set_device_state(target_states: dict) -> (bool, str):
    """
    Change device states.

    :param target_states: New device state. Pass channels as keys and new states as values. E.g. {"ch1": "On"}

    :return: Tuple of success flag and message. True if successfully changed states, False if not.

    """

    logger.debug(f"Attempting to change states of light to {target_states}.")

    different: bool = False
    with open(DEVICE_PATH) as file:
        current_states = json.loads(file.read())

    target_attribute_key: list = []
    for key in target_states.keys():
        target_attribute_key.append(key)

    target_attribute_value: list = []
    for value in target_states.values():
        target_attribute_value.append(value)

    # check that Attribute in Attributes list
    if target_attribute_key[0] not in current_states.keys():
        message: str = (
            f"Attribute '{target_attribute_key}' not in light attributes list "
            f"'{list(current_states.keys())}'!"
        )
        return False, message

    # check attributes values - illumination
    if target_attribute_key[0] == "illumination":
        try:
            target_attribute_value: int = int(target_attribute_value[0])
        except ValueError:
            message = "Attribute value should be a number."
            return False, message

        if target_attribute_value > 10 or target_attribute_value < 0:
            message = "Attribute value should be between 0 and 10"
            return False, message

    # check attributes values - color
    if target_attribute_key[0] == "color":
        try:
            target_value_string: str = target_attribute_value[0]
            target_value_array = target_value_string.split(",")
            for i in range(len(target_value_array)):
                target_value_array[i] = int(target_value_array[i].strip())
        except ValueError:
            message = "Attribute value should be a number."
            return False, message

        for number in target_value_array:
            if number > 255 or number < 0:
                message = "Attribute value should be between 0 and 255"
                return False, message
    if target_states[target_attribute_key[0]] != current_states[target_attribute_key[0]]:
        current_states[target_attribute_key[0]] = target_states[target_attribute_key[0]]
        different = True

    if not different:
        message = f"Light already have this state."
        return False, message

    with open(DEVICE_PATH, "w") as file:
        file.write(json.dumps(current_states))

    message = f"Successfully modified states of light! New device states: '{current_states}'."
    return True, message


def get_device_state(attribute: str | None = None) -> (bool, dict | str):
    """
    Get device states from a device emulating file.

    :param attribute: Exact attribute of a device.

    :return: Device states as a dictionary or a device attribute state.

    """

    logger.debug("Reading device states.")
    with open(DEVICE_PATH) as file:
        states = json.loads(file.read())
    if attribute:
        if attribute not in states.keys():
            success_flag: bool = False
            message: str = f"No attribute '{attribute}' found in light states'!"
        else:
            success_flag: bool = True
            message: str = states[attribute]
    else:
        success_flag: bool = True
        message: dict = states

    return success_flag, str(message)


def watch_device_state(callback: any) -> None:
    """
    Starts a file state watcher. Each time a file modified - calls a `callback` function passed as an argument.

    :param callback: Callback class with a method to execute at file change.

    """

    try:
        loop = asyncio.get_event_loop()
        logger.debug("Creating WatchManager object.")
        wm = pyinotify.WatchManager()

        logger.debug("Setting up a notifier.")
        notifier = pyinotify.AsyncioNotifier(wm, loop, default_proc_fun=callback)

        logger.debug(f"Starting watcher for light.")
        wm.add_watch(DEVICE_PATH, pyinotify.IN_CLOSE_WRITE)
        logger.info(f"Watcher for device set!")
    except Exception as e:
        logger.error(f"Error in a Watch Manager: {e}")
        notifier.stop()
