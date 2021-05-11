#### Parser Content
```Java
{
Name = crowdstrike-process-created
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "process-created"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":""", """"ProcessRollup2"""" ]
    Fields = [
      """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
      """"aip":\s{0,100}"({host}[^"]+)""",
      """"aip":\s{0,100}"({dest_ip}[^"]+)"""
      """"timestamp":\s{0,100}"({time}\d{1,100})""",
      """"event_simpleName":\s{0,100}"({event_code}[^"]+)""",
      """"aid":\s{0,100}"({aid}[^"]+)""",
      """"CommandLine":\s{0,100}"\s{0,100}({command_line}[^,]+?)\s{0,100}"{0,20}
```