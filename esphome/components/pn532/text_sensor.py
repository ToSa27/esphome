import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import text_sensor
from esphome.const import CONF_UID, CONF_ID, CONF_CARD_TYPE
from . import pn532_ns, PN532

DEPENDENCIES = ['pn532']

CONF_PN532_ID = 'pn532_id'


def validate_card_type(value):
    value = cv.string_strict(value)
    if value not in ['classic', 'ev1_des', 'ev1_aes', 'ev1_des_rnd', 'ev1_aes_rnd']:
        raise cv.Invalid("Valid cart types: classic, ev1_des, ev1_des_rnd, ev1_aes or ev1_aes_rnd.")
    return value


PN532TextSensor = pn532_ns.class_('PN532TextSensor', text_sensor.TextSensor)

CONFIG_SCHEMA = text_sensor.TEXT_SENSOR_SCHEMA.extend({
    cv.GenerateID(): cv.declare_id(PN532TextSensor),
    cv.GenerateID(CONF_PN532_ID): cv.use_id(PN532),
    cv.Required(CONF_UID): validate_uid,
    cv.Optional(CONF_CARD_TYPE): validate_card_type,
})


def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    yield text_sensor.register_text_sensor(var, config)

    hub = yield cg.get_variable(config[CONF_PN532_ID])
    cg.add(hub.register_text_sensor(var))
    if CONF_CARD_TYPE in config:
        cg.add(var.set_card_type(config[CONF_CARD_TYPE]))
