#### Parser Content
```Java
{
Name = cisco-process-network
  Vendor = Cisco
  Product = AnyConnect
  Lms = Direct
  DataType = "process-network"
  IsHVF = true
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """ pn=""", """ ppn=""", """fv=nvzFlow_v3""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\sfet='*(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d\d:\d\d:\d\d \d{1,100})""",
    """\ssa="({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\ssa="({host}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sda="({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\ssp=({src_port}\d{1,100})""",
    """\sdp=({dest_port}\d{1,100})""",
    """\sibc=({bytes_in}\d{1,100})""",
    """\sobc=({bytes_out}\d{1,100})""",
    """\spr=({packet_rate}\d{1,100})""",
    """\spn='*(?=\w)({process_name}[^']{1,2000})'*\s""",
    """\sppn='*(?=\w)({parent_process_name}[^']{1,2000})'*\s""",
    """\spph="({parent_process_hash}([^"]{1,2000}))"""",
    """\sdh="({dest_host}([^"]{1,2000}))"""",
    """\sph="?({process_hash}([^\s]{1,2000}))"?\s""",
    """\sppap='(?:[^']{1,2000}[\s])?'*({user}[^\s']{1,2000})""",
    """\sppaa='(?:[^']{1,2000}[\s])?'*({domain}[^\s']{1,2000})""",
    """\spaa='(?:[^']{1,2000}[\s])?'(?:[^']{1,2000}[\s])?({domain}[^\s']{1,2000})""",
    """\spap='(?:[^']{1,2000}[\s])?'(?:[^']{1,2000}[\s])?({user}[^\s']{1,2000})""",
    """\sudid=({udid}([^\s]{1,2000}))\s""",
    """\smnl='(?=\w)({module_hash_names}[^']{1,2000}?)\s{0,100}'\s""",
    """\svsn=({virtual_station_name}[^\s]{1,2000})\s""",
    """\sosn=({os_name}[^\s]{1,2000})""",
    """\sosv=({os_version}[^\s]{1,2000})\s""",
    """\sose=({os_environment}[^\s]{1,2000})\s""",
    """\ssm=({system_manufacturer}[^\s]{1,2000})\s""",
    """\sst=({system_type}[^\s]{1,2000})\s"""
  ]
}
```