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
    """rt=({time}\d{1,100})"""
    """NSX FW\|[^\|]{0,2000}\|({action}[^\|]{1,2000})"""
    """categoryOutcome=\/({outcome}[^\s]{0,2000})""",
    """eventId=({event_code}[^\s]{1,2000})""",
    """proto=({protocol}[^\s]{1,2000})""",
    """cs1=({additional_info}[^\s]{1,2000})""",
    """cs2=({host}[^\s]{1,2000})""",
    """src=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """spt=({src_port}\d{1,100})""",
    """dst=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """dpt=({dest_port}\d{1,100})"""
    """categoryBehavior=\/({activity}[^\s]{1,2000})""",
    """dtz=({dest_country}[^\s]{1,2000})"""
  ]
}
```