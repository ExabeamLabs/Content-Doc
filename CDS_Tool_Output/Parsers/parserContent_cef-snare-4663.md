#### Parser Content
```Java
{
Name = cef-snare-4663
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-4663"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|Snare|""","""|Microsoft-Windows-Security-Auditing:4663|""" ]
  Fields = [ """exabeam_EventTime=({eventtime}\d+)""",
    """({event_name}An attempt was made to access an object)""",
    """\sexternalId=({event_code}\d+)""",
    """\srt=({time}\d+)""",
    """\sdntdom=({domain}[^\s]+)""",
    """\sduser=({user}.+?)\s+\w+=""",
    """\sduid=({logon_id}[^\s]+)""",
    """\scs1=({accesses}.+?)\s+\w+=""",
    """\sdvc=({host}[a-fA-F:\d.]+)""",
    """\sdvchost=({host}[^\s]+)""",
    """\sfname=({file_path}.+?)\s+(?:$|\w+=)""",
    """\sfname=({file_parent}.+?)\\+(?:[^\\=]+?)\s+(?:$|\w+=)""",
    """\sfname=[^=]*\\({file_name}.*?({file_ext}\.[^\\:\s.]+)?)\s+(?:$|\w+=)""",
    """\scs3=({access_mask}\w+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```