#### Parser Content
```Java
{
Name = s-onguard-physical-badge-access
  Vendor = Onguard
  Product = Onguard
  Lms = Splunk
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.S"
  Conditions = [ """, EVDESCR="""", """, SSNO="""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\WEVENT_LOCAL_TIME="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)""",
    """\WLASTNAME="({last_name}[^"]+?)\s*"""",
    """\WFIRSTNAME="({first_name}[^"]+?)\s*"""",
    """\WEVDESCR="({outcome}[^"]+)""",
    """\WCARDNUM="({badge_id}[^"]+)""",
    """\WSSNO="({user}[^"]+)"""",
    """\WSERIALNUM="({serial_num}[^"]+)""",
    """\WREADERDESC="({location_door}[^"]+)""",
    """\WDEVID="({devid}[^"]+)""",
    """\WNAME="({location_building}[^"]+)""",
    """\WSEQ="({seq_num}[^"]+)""",
    """({direction}IN|OUT)""",
  ]
}
```