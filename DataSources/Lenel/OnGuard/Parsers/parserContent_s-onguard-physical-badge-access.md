#### Parser Content
```Java
{
Name = s-onguard-physical-badge-access
  Vendor = Lenel
  Product = OnGuard
  Lms = Splunk
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.S"
  Conditions = [ """, EVDESCR="""", """, SSNO="""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\WEVENT_LOCAL_TIME="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """\WLASTNAME="({last_name}[^"]+?)\s{0,100}"""",
    """\WFIRSTNAME="({first_name}[^"]+?)\s{0,100}"""",
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