# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: pogoprotos/data/logs/fort_search_log_entry.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from pogoprotos.data import pokemon_data_pb2 as pogoprotos_dot_data_dot_pokemon__data__pb2
from pogoprotos.inventory.item import item_data_pb2 as pogoprotos_dot_inventory_dot_item_dot_item__data__pb2
from pogoprotos.map.fort import fort_type_pb2 as pogoprotos_dot_map_dot_fort_dot_fort__type__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='pogoprotos/data/logs/fort_search_log_entry.proto',
  package='pogoprotos.data.logs',
  syntax='proto3',
  serialized_pb=_b('\n0pogoprotos/data/logs/fort_search_log_entry.proto\x12\x14pogoprotos.data.logs\x1a\"pogoprotos/data/pokemon_data.proto\x1a)pogoprotos/inventory/item/item_data.proto\x1a#pogoprotos/map/fort/fort_type.proto\"\xe5\x03\n\x12\x46ortSearchLogEntry\x12?\n\x06result\x18\x01 \x01(\x0e\x32/.pogoprotos.data.logs.FortSearchLogEntry.Result\x12\x0f\n\x07\x66ort_id\x18\x02 \x01(\t\x12\x32\n\x05items\x18\x03 \x03(\x0b\x32#.pogoprotos.inventory.item.ItemData\x12\x0c\n\x04\x65ggs\x18\x04 \x01(\x05\x12\x32\n\x0cpokemon_eggs\x18\x05 \x03(\x0b\x32\x1c.pogoprotos.data.PokemonData\x12\x30\n\tfort_type\x18\x06 \x01(\x0e\x32\x1d.pogoprotos.map.fort.FortType\x12:\n\rawarded_items\x18\x07 \x03(\x0b\x32#.pogoprotos.inventory.item.ItemData\x12\x38\n\x0b\x62onus_items\x18\x08 \x03(\x0b\x32#.pogoprotos.inventory.item.ItemData\x12=\n\x10team_bonus_items\x18\t \x03(\x0b\x32#.pogoprotos.inventory.item.ItemData\" \n\x06Result\x12\t\n\x05UNSET\x10\x00\x12\x0b\n\x07SUCCESS\x10\x01\x62\x06proto3')
  ,
  dependencies=[pogoprotos_dot_data_dot_pokemon__data__pb2.DESCRIPTOR,pogoprotos_dot_inventory_dot_item_dot_item__data__pb2.DESCRIPTOR,pogoprotos_dot_map_dot_fort_dot_fort__type__pb2.DESCRIPTOR,])
_sym_db.RegisterFileDescriptor(DESCRIPTOR)



_FORTSEARCHLOGENTRY_RESULT = _descriptor.EnumDescriptor(
  name='Result',
  full_name='pogoprotos.data.logs.FortSearchLogEntry.Result',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='UNSET', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SUCCESS', index=1, number=1,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=644,
  serialized_end=676,
)
_sym_db.RegisterEnumDescriptor(_FORTSEARCHLOGENTRY_RESULT)


_FORTSEARCHLOGENTRY = _descriptor.Descriptor(
  name='FortSearchLogEntry',
  full_name='pogoprotos.data.logs.FortSearchLogEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='result', full_name='pogoprotos.data.logs.FortSearchLogEntry.result', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='fort_id', full_name='pogoprotos.data.logs.FortSearchLogEntry.fort_id', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='items', full_name='pogoprotos.data.logs.FortSearchLogEntry.items', index=2,
      number=3, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='eggs', full_name='pogoprotos.data.logs.FortSearchLogEntry.eggs', index=3,
      number=4, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='pokemon_eggs', full_name='pogoprotos.data.logs.FortSearchLogEntry.pokemon_eggs', index=4,
      number=5, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='fort_type', full_name='pogoprotos.data.logs.FortSearchLogEntry.fort_type', index=5,
      number=6, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='awarded_items', full_name='pogoprotos.data.logs.FortSearchLogEntry.awarded_items', index=6,
      number=7, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='bonus_items', full_name='pogoprotos.data.logs.FortSearchLogEntry.bonus_items', index=7,
      number=8, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='team_bonus_items', full_name='pogoprotos.data.logs.FortSearchLogEntry.team_bonus_items', index=8,
      number=9, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _FORTSEARCHLOGENTRY_RESULT,
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=191,
  serialized_end=676,
)

_FORTSEARCHLOGENTRY.fields_by_name['result'].enum_type = _FORTSEARCHLOGENTRY_RESULT
_FORTSEARCHLOGENTRY.fields_by_name['items'].message_type = pogoprotos_dot_inventory_dot_item_dot_item__data__pb2._ITEMDATA
_FORTSEARCHLOGENTRY.fields_by_name['pokemon_eggs'].message_type = pogoprotos_dot_data_dot_pokemon__data__pb2._POKEMONDATA
_FORTSEARCHLOGENTRY.fields_by_name['fort_type'].enum_type = pogoprotos_dot_map_dot_fort_dot_fort__type__pb2._FORTTYPE
_FORTSEARCHLOGENTRY.fields_by_name['awarded_items'].message_type = pogoprotos_dot_inventory_dot_item_dot_item__data__pb2._ITEMDATA
_FORTSEARCHLOGENTRY.fields_by_name['bonus_items'].message_type = pogoprotos_dot_inventory_dot_item_dot_item__data__pb2._ITEMDATA
_FORTSEARCHLOGENTRY.fields_by_name['team_bonus_items'].message_type = pogoprotos_dot_inventory_dot_item_dot_item__data__pb2._ITEMDATA
_FORTSEARCHLOGENTRY_RESULT.containing_type = _FORTSEARCHLOGENTRY
DESCRIPTOR.message_types_by_name['FortSearchLogEntry'] = _FORTSEARCHLOGENTRY

FortSearchLogEntry = _reflection.GeneratedProtocolMessageType('FortSearchLogEntry', (_message.Message,), dict(
  DESCRIPTOR = _FORTSEARCHLOGENTRY,
  __module__ = 'pogoprotos.data.logs.fort_search_log_entry_pb2'
  # @@protoc_insertion_point(class_scope:pogoprotos.data.logs.FortSearchLogEntry)
  ))
_sym_db.RegisterMessage(FortSearchLogEntry)


# @@protoc_insertion_point(module_scope)
