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
    """shost=({src_host}.+?)\s{1,100}\w+="""
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""
    """({outcome}Allowed)"""
    """({event_name}Print Control Event)"""
    """({severity}Low)"""
    """suser=({user}[^\s]{1,2000})\s{1,100}\w+="""
    """suid=({suid}[^\s]{1,2000})\s{1,100}\w+="""
    """fname=({file_name}.+?)\s{1,100}\w+="""
    """fsize=({file_size}.+?)\s{1,100}\w+="""
    """cs1=({device_type}.+?)\s{1,100}\w+="""
    """cs2=({group_name}.+?)\s{1,100}\w+="""
    """cs6=({action}.+?)\s{1,100}\w+="""
    """src=({src_ip}.+?)\s{1,100}\w+="""
    """smac=({src_mac}.+?)\s{1,100}\w+="""
    """cs3=({device_id}.+?)\s{1,100}\w+="""
    """cn1=({num_pages}.+?)\s{1,100}\w+="""
    """cn2=({num_pages}.+?)\s{1,100}\w+="""
    """dvchost=({host}.+?)\s{1,100}\w+="""
    """dvc=({host}.+?)\s{1,100}\w+="""
  ]
  DupFields = ["file_name->object"]
}
```