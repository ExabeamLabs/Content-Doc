#### Parser Content
```Java
{
Name = checkpoint-network-alert-2
  Conditions = [ """product:""", """alert:"alert"""" ]
}

${CheckpointParserTemplates.checkpoint-network-alert} {
  Name = checkpoint-network-alert-4
  Conditions = [ """product:""", """SmartDefense""", """CheckPoint""", """sequencenum""", """attack:""" ]
}

${CheckpointParserTemplates.checkpoint-auth} {
  Name = checkpoint-vpn-login-6
  DataType = "vpn-login"
  Conditions = [ """CheckPoint""", """product:"""", """action:"Log In"""", """vpn_""" ]
  Fields = ${CheckpointParserTemplates.checkpoint-auth.Fields}[
    """action:"+({activity}[^"]+)"""
  ]
  DupFields = [ "activity->event_name" ]
}

${CheckpointParserTemplates.checkpoint-auth} {
  Name = checkpoint-auth-successful
  DataType = "authentication-successful"
  Conditions = [ """CheckPoint""", """product:"""", """action:"Log In"""" ] 
}

${CheckpointParserTemplates.checkpoint-auth} {
  Name = checkpoint-vpn-connection
  DataType = "vpn-connection"
  Conditions = [ """CheckPoint""", """product:"""", """action:"Update"""", """product:"Identity Awareness"""", """auth_status:"Successful Login"""", """identity_src:"VPN Remote Access"""" ]
}

${CheckpointParserTemplates.checkpoint-auth} {
  Name = checkpoint-auth-successful-1
  DataType = "authentication-successful"
  Conditions = [ """CheckPoint""", """product:"""", """action:"Update"""", """product:"Identity Awareness"""", """auth_status:"Successful Login"""" ]
}

${CheckpointParserTemplates.checkpoint-auth} {
  Name = checkpoint-auth-failed
  DataType = "authentication-failed"  
  Conditions = [ """CheckPoint""", """product:"""", """action:"Failed Log In"""" ] 
}

${CheckpointParserTemplates.checkpoint-firewall-1}{
  Name = checkpoint-network-connection-4
  Conditions = [ """CheckPoint""", """"SMTP transparent proxy"""" ]
}
```