#### Parser Content
```Java
{
Name = checkpoint-vpn-login-6
  DataType = "vpn-login"
  Conditions = [ """CheckPoint""", """product:"""", """action:"Log In"""", """vpn_""" ]
  Fields = ${CheckpointParserTemplates.checkpoint-auth.Fields}[
    """action:"+({activity}[^"]+)"""
  ]
  DupFields = [ "activity->event_name" ]
}
```