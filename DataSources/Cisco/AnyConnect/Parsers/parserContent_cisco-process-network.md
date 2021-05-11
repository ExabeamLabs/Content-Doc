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
    """exabeam_host=({host}[^\s]+)""",
    """\sfet='*(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d\d:\d\d:\d\d \d{1,100})""",
    """\ssa="({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\ssa="({host}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sda="({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\ssp=({src_port}\d{1,100})""",
    """\sdp=({dest_port}\d{1,100})""",
    """\sibc=({bytes_in}\d{1,100})""",
    """\sobc=({bytes_out}\d{1,100})""",
    """\spr=({packet_rate}\d{1,100})""",
    """\spn='*(?=\w)({process_name}[^']+)'*\s""",
    """\sppn='*(?=\w)({parent_process_name}[^']+)'*\s""",
    """\spph="({parent_process_hash}([^"]+))"""",
    """\sdh="({dest_host}([^"]+))"""",
    """\sph="?({process_hash}([^\s]+))"?\s""",
    """\sppap='(?:[^']+[\s])?'*({user}[^\s']+)""",
    """\sppaa='(?:[^']+[\s])?'*({domain}[^\s']+)""",
    """\spaa='(?:[^']+[\s])?'(?:[^']+[\s])?({domain}[^\s']+)""",
    """\spap='(?:[^']+[\s])?'(?:[^']+[\s])?({user}[^\s']+)""",
    """\sudid=({udid}([^\s]+))\s""",
    """\smnl='(?=\w)({module_hash_names}[^']+?)\s{0,100}'\s""",
    """\svsn=({virtual_station_name}[^\s]+)\s""",
    """\sosn=({os_name}[^\s]+)""",
    """\sosv=({os_version}[^\s]+)\s""",
    """\sose=({os_environment}[^\s]+)\s""",
    """\ssm=({system_manufacturer}[^\s]+)\s""",
    """\sst=({system_type}[^\s]+)\s"""
  ]
}
```