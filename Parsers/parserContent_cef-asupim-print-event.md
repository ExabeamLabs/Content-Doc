#### Parser Content
```Java
{
Name = cef-asupim-print-event
  Vendor = ASUPIM
  Product = ASUPIM
  Lms = Direct
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """Print Control Event""", """|ASUPIM|ASUPIM|""" ]
  Fields = [
    """shost=({src_host}.+?)\s+\w+="""
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""
    """({outcome}Allowed)"""
    """({event_name}Print Control Event)"""
    """({severity}Low)"""
    """suser=({user}[^\s]+)\s+\w+="""
    """suid=({suid}[^\s]+)\s+\w+="""
    """fname=({file_name}.+?)\s+\w+="""
    """fsize=({file_size}.+?)\s+\w+="""
    """cs1=({device_type}.+?)\s+\w+="""
    """cs2=({group_name}.+?)\s+\w+="""
    """cs6=({action}.+?)\s+\w+="""
    """src=({src_ip}.+?)\s+\w+="""
    """smac=({src_mac}.+?)\s+\w+="""
    """cs3=({device_id}.+?)\s+\w+="""
    """cn1=({num_pages}.+?)\s+\w+="""
    """cn2=({num_pages}.+?)\s+\w+="""
    """dvchost=({host}.+?)\s+\w+="""
    """dvc=({host}.+?)\s+\w+="""
  ]
  DupFields = ["file_name->object"]
}
```