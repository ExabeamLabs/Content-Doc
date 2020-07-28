#### Parser Content
```Java
{
Name = zscaler-activity
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "EEE MMM dd HH:mm:ss yyyy"
  Conditions = ["""InternalReason""" , """Client""", """IP""", """ConnectorZENSetupTime"""]
  Fields = [
     """Host":\s*"({host}[^"]+)"""",
     """({time}\w{3}\s\d+\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
     """IPProtocol":\s*({protocol}[^"]+),"""
     """ServerIP":\s*"({dest_ip}[^"]+)"""",
     """ConnectorPort":\s*({src_port}[^\s]+),""",
     """ServerPort":\s*({dest_port}[^\s]+),""",
     """Policy":\s*"\s*({policy}[^"]+)"""",
     """ConnectionStatus":\s*"({outcome}[^"]+)""""
     """"LogTimestamp":\s*"({time}[^"]+)""""
     """"SessionID":\s*"({session_id}[^"]+)""""
     """"ConnectionID":\s*"({connection_id}[^"]+)""""
     """"InternalReason":\s*"({reason}[^"]+)""""
     """"Username":\s*"(({user_email}[^"@]+?@[^"]+)|({user}[^"]+))""""
     """"ServicePort":\s*"({dest_port}[^"]+)""""
     """"ClientPublicIP":\s*"({src_ip}[^"]+)""""
     """"ClientCountryCode":\s*"({src_country}[^"]+)""""
     """"ClientZEN":\s*"({zen_code}[^"]+)""""
     """"Connector":\s*"(0|({host}[^"]+))""""
     """"ConnectorZEN":\s*"({zen_con_code}[^"]+)""""
     """"ConnectorIP":\s*"({host_ip}[^"]+)""""
     """"Host":\s*"({dest_host}[^"]+)""""
     """"Application":\s*"({app}[^"]+)""""
     """"AppGroup":\s*"({app_group}[^"]+)""""
     """"TimestampConnectionStart":\s*"({event_start_time}[^"]+)""""
     """"TimestampConnectionEnd":\s*"({event_stop_time}[^"]+)""""
     """"ZENTotalBytesRxClient":\s*({rx_client_total_bytes}\d+)"""
     """"ZENTotalBytesTxClient":\s*({tx_client_total_bytes}\d+)"""
     """"ZENTotalBytesRxConnector":\s*({rx_connector_total_bytes}\d+)"""
     """"ZENTotalBytesTxConnector":\s*({tx_connector_total_bytes}\d+)"""
     """"PolicyProcessingTime":\s*({policy_runtime}\d+)"""
     """"CAProcessingTime":\s*({ca_runtime}\d+)"""
     """"AppLearnTime":\s*({app_learntime}\d+)"""
     

  ]
  DupFields = ["outcome->conn_status", "app_group->activity_type", "rx_connector_total_bytes->bytes_in", "tx_connector_total_bytes->bytes_out"]
 
}
```