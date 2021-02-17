#### Parser Content
```Java
{
Name = cef-nsx-fw-logs-1
  Product = NSX FW
  Vendor = VMware
  Lms = ArcSight
  DataType = "network-connection"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""" ,"""|VMware|NSX FW|""", """destinationZoneURI="""]
  Fields = [
    """rt=({time}\d+)"""
    """NSX FW\|[^\|]*\|({action}[^\|]+)"""
    """categoryOutcome=\/({outcome}[^\s]*)""",
    """eventId=({event_code}[^\s]+)""",
    """proto=({protocol}[^\s]+)""",
    """cs1=({additional_info}[^\s]+)""",
    """cs2=({host}[^\s]+)""",
    """src=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """spt=({src_port}\d+)""",
    """dst=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """dpt=({dest_port}\d+)"""
    """categoryBehavior=\/({activity}[^\s]+)""",
    """dtz=({dest_country}[^\s]+)"""
  ]
}
```