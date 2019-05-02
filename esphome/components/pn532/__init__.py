import esphome.codegen as cg
import esphome.config_validation as cv
from esphome import automation
from esphome.automation import Condition, maybe_simple_id
from esphome.components import spi
from esphome.const import CONF_ID, CONF_ON_TAG, CONF_TRIGGER_ID, CONF_CARD_TYPE, CONF_MASTER_KEY, CONF_APPLICATION_KEY, CONF_VALUE_KEY, CONF_APPLICATION_ID, CONF_FILE_ID, CONF_KEY_VERSION
from string import hexdigits

DEPENDENCIES = ['spi']
AUTO_LOAD = ['binary_sensor']
MULTI_CONF = True

pn532_ns = cg.esphome_ns.namespace('pn532')
PN532 = pn532_ns.class_('PN532', cg.PollingComponent, spi.SPIDevice)
PN532Trigger = pn532_ns.class_('PN532Trigger', automation.Trigger.template(cg.std_string))
PN532EncodeAction = pn532_ns.class_('PN532EncodeAction', automation.Action)
PN532EncodingCondition = pn532_ns.class_('PN532EncodingCondition', Condition)

def validate_card_type(value):
    value = cv.string_strict(value)
    if value not in ['classic', 'ev1_des', 'ev1_aes', 'ev1_des_rnd', 'ev1_aes_rnd']:
        raise cv.Invalid("Valid cart types: classic, ev1_des, ev1_des_rnd, ev1_aes or ev1_aes_rnd.")
    return value

def validate_hex(value, length):
    value = cv.string_strict(value)
    if len(value) != length * 2:
        raise cv.Invalid("Invalid length - must be a hex string with {0} hex chars ({1} byte).".format(length * 2, length))
    for c in value:
        if c not in hexdigits:
            raise cv.Invalid("Invalid character - not a hex character: {0}.".format(c))
    return value

def validate_hex24(value):
    return validate_hex(value, 24)

def validate_hex3(value):
    return validate_hex(value, 3)

CONFIG_SCHEMA = cv.Schema({
    cv.GenerateID(): cv.declare_id(PN532),
    cv.Optional(CONF_ON_TAG): automation.validate_automation({
        cv.GenerateID(CONF_TRIGGER_ID): cv.declare_id(PN532Trigger),
    }),
    cv.Optional(CONF_CARD_TYPE): validate_card_type,
    cv.Optional(CONF_MASTER_KEY): validate_hex24,
    cv.Optional(CONF_APPLICATION_KEY): validate_hex24,
    cv.Optional(CONF_VALUE_KEY): validate_hex24,
    cv.Optional(CONF_APPLICATION_ID): validate_hex3,
    cv.Optional(CONF_FILE_ID): cv.All(cv.int_, cv.Range(min=0, max=32)),
    cv.Optional(CONF_KEY_VERSION): cv.All(cv.int_, cv.Range(min=1, max=255)),
}).extend(cv.polling_component_schema('1s')).extend(spi.SPI_DEVICE_SCHEMA)

PN532_ACTION_SCHEMA = maybe_simple_id({
    cv.Required(CONF_ID): cv.use_id(PN532),
})

def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    yield cg.register_component(var, config)
    yield spi.register_spi_device(var, config)

    for conf in config.get(CONF_ON_TAG, []):
        trigger = cg.new_Pvariable(conf[CONF_TRIGGER_ID])
        cg.add(var.register_trigger(trigger))
        yield automation.build_automation(trigger, [(cg.std_string, 'x')], conf)

    if CONF_CARD_TYPE in config:
        cg.add(var.set_card_type(config[CONF_CARD_TYPE]))

    if CONF_MASTER_KEY in config:
        cg.add(var.set_master_key(config[CONF_MASTER_KEY]))

    if CONF_APPLICATION_KEY in config:
        cg.add(var.set_application_key(config[CONF_APPLICATION_KEY]))

    if CONF_VALUE_KEY in config:
        cg.add(var.set_value_key(config[CONF_VALUE_KEY]))

    if CONF_APPLICATION_ID in config:
        cg.add(var.set_application_id(config[CONF_APPLICATION_ID]))

    if CONF_FILE_ID in config:
        cg.add(var.set_file_id(config[CONF_FILE_ID]))

    if CONF_KEY_VERSION in config:
        cg.add(var.set_key_version(config[CONF_KEY_VERSION]))

@automation.register_action('pn532.encode', PN532EncodeAction, PN532_ACTION_SCHEMA)

@automation.register_condition('pn532.encoding', PN532EncodingCondition, PN532_ACTION_SCHEMA)
def pn532_encoding_to_code(config, condition_id, template_arg, args):
    paren = yield cg.get_variable(config[CONF_ID])
    yield cg.new_Pvariable(condition_id, template_arg, paren)
