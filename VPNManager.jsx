import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button.jsx'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog.jsx'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table.jsx'
import { 
  Plus, 
  Trash2, 
  QrCode, 
  Download, 
  Eye, 
  EyeOff,
  Users,
  Wifi,
  Lock,
  Key,
  Copy,
  CheckCircle,
  XCircle,
  Activity,
  RotateCcw
} from 'lucide-react'

const API_BASE = 'http://localhost:5001/api/v1'

function VPNManager() {
  const [users, setUsers] = useState([])
  const [vpnStatus, setVpnStatus] = useState({ status: 'unknown' })
  const [loading, setLoading] = useState(false)
  const [showAddUser, setShowAddUser] = useState(false)
  const [showConfig, setShowConfig] = useState(false)
  const [selectedUser, setSelectedUser] = useState(null)
  const [userConfig, setUserConfig] = useState(null)
  const [newUserName, setNewUserName] = useState('')
  const [copied, setCopied] = useState(false)

  // Fetch VPN status
  const fetchVPNStatus = async () => {
    try {
      const response = await fetch(`${API_BASE}/wireguard/status`)
      const data = await response.json()
      setVpnStatus(data)
    } catch (error) {
      console.error('Error fetching VPN status:', error)
      setVpnStatus({ status: 'error', error: error.message })
    }
  }

  // Fetch VPN users
  const fetchUsers = async () => {
    try {
      const response = await fetch(`${API_BASE}/wireguard/users`)
      const data = await response.json()
      setUsers(Array.isArray(data) ? data : [])
    } catch (error) {
      console.error('Error fetching VPN users:', error)
      setUsers([])
    }
  }

  // Create new VPN user
  const createUser = async () => {
    if (!newUserName.trim()) return

    setLoading(true)
    try {
      const response = await fetch(`${API_BASE}/wireguard/users`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ name: newUserName })
      })

      if (response.ok) {
        const newUser = await response.json()
        setUsers(prev => [...prev, newUser])
        setNewUserName('')
        setShowAddUser(false)
      } else {
        const error = await response.json()
        console.error('Error creating user:', error)
      }
    } catch (error) {
      console.error('Error creating user:', error)
    } finally {
      setLoading(false)
    }
  }

  // Delete VPN user
  const deleteUser = async (userName) => {
    if (!confirm(`Are you sure you want to delete user "${userName}"?`)) return

    try {
      const response = await fetch(`${API_BASE}/wireguard/users/${userName}`, {
        method: 'DELETE'
      })

      if (response.ok) {
        setUsers(prev => prev.filter(user => user.name !== userName))
      } else {
        const error = await response.json()
        console.error('Error deleting user:', error)
      }
    } catch (error) {
      console.error('Error deleting user:', error)
    }
  }

  // Get user configuration and QR code
  const getUserConfig = async (userName) => {
    setLoading(true)
    try {
      const response = await fetch(`${API_BASE}/wireguard/users/${userName}/config`)
      const data = await response.json()
      
      if (response.ok) {
        setUserConfig(data)
        setSelectedUser(userName)
        setShowConfig(true)
      } else {
        console.error('Error getting user config:', data.error)
      }
    } catch (error) {
      console.error('Error getting user config:', error)
    } finally {
      setLoading(false)
    }
  }

  // Copy configuration to clipboard
  const copyConfig = async () => {
    if (userConfig?.config_content) {
      try {
        await navigator.clipboard.writeText(userConfig.config_content)
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
      } catch (error) {
        console.error('Error copying to clipboard:', error)
      }
    }
  }

  // Download configuration file
  const downloadConfig = () => {
    if (userConfig?.config_content && selectedUser) {
      const blob = new Blob([userConfig.config_content], { type: 'text/plain' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${selectedUser}.conf`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    }
  }

  const getStatusColor = (status) => {
    switch (status) {
      case 'active': return 'text-green-600'
      case 'inactive': return 'text-red-600'
      case 'error': return 'text-orange-600'
      default: return 'text-gray-600'
    }
  }

  const getStatusIcon = (status) => {
    switch (status) {
      case 'active': return <CheckCircle className="h-4 w-4" />
      case 'inactive': return <XCircle className="h-4 w-4" />
      case 'error': return <Activity className="h-4 w-4" />
      default: return <Activity className="h-4 w-4" />
    }
  }

  useEffect(() => {
    fetchVPNStatus()
    fetchUsers()
  }, [])

  return (
    <div className="space-y-6">
      {/* VPN Status Card */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center space-x-2">
                <Lock className="h-5 w-5" />
                <span>WireGuard VPN Status</span>
              </CardTitle>
              <CardDescription>
                Secure VPN tunnel management
              </CardDescription>
            </div>
            <div className="flex items-center space-x-4">
              <div className={`flex items-center space-x-1 ${getStatusColor(vpnStatus.status)}`}>
                {getStatusIcon(vpnStatus.status)}
                <span className="text-sm font-medium capitalize">{vpnStatus.status}</span>
              </div>
              <Button variant="outline" size="sm" onClick={fetchVPNStatus}>
                <RotateCcw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{users.length}</div>
              <div className="text-sm text-muted-foreground">Active Users</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">
                {vpnStatus.listen_port || '51820'}
              </div>
              <div className="text-sm text-muted-foreground">Listen Port</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">10.0.0.0/24</div>
              <div className="text-sm text-muted-foreground">VPN Network</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600">
                {vpnStatus.status === 'active' ? 'Online' : 'Offline'}
              </div>
              <div className="text-sm text-muted-foreground">Service Status</div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Users Management */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center space-x-2">
                <Users className="h-5 w-5" />
                <span>VPN Users</span>
              </CardTitle>
              <CardDescription>
                Manage VPN user access and configurations
              </CardDescription>
            </div>
            <Dialog open={showAddUser} onOpenChange={setShowAddUser}>
              <DialogTrigger asChild>
                <Button>
                  <Plus className="h-4 w-4 mr-2" />
                  Add User
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Add New VPN User</DialogTitle>
                  <DialogDescription>
                    Create a new WireGuard VPN user with automatic key generation
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4">
                  <div>
                    <Label htmlFor="username">User Name</Label>
                    <Input
                      id="username"
                      placeholder="e.g., John's iPhone, Office Laptop"
                      value={newUserName}
                      onChange={(e) => setNewUserName(e.target.value)}
                    />
                  </div>
                  <div className="flex justify-end space-x-2">
                    <Button variant="outline" onClick={() => setShowAddUser(false)}>
                      Cancel
                    </Button>
                    <Button onClick={createUser} disabled={loading || !newUserName.trim()}>
                      {loading ? 'Creating...' : 'Create User'}
                    </Button>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </CardHeader>
        <CardContent>
          {users.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Users className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No VPN users configured</p>
              <p className="text-sm">Click "Add User" to create your first VPN user</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User Name</TableHead>
                  <TableHead>IP Address</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((user) => (
                  <TableRow key={user.name || user.id}>
                    <TableCell className="font-medium">{user.name}</TableCell>
                    <TableCell>
                      <Badge variant="secondary">{user.allowed_ips}</Badge>
                    </TableCell>
                    <TableCell>
                      {user.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'}
                    </TableCell>
                    <TableCell>
                      <Badge variant={user.status === 'enabled' ? 'default' : 'secondary'}>
                        {user.status || 'enabled'}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex space-x-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => getUserConfig(user.name)}
                        >
                          <QrCode className="h-3 w-3 mr-1" />
                          Config
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => deleteUser(user.name)}
                        >
                          <Trash2 className="h-3 w-3 mr-1" />
                          Delete
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Configuration Dialog */}
      <Dialog open={showConfig} onOpenChange={setShowConfig}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center space-x-2">
              <Key className="h-5 w-5" />
              <span>VPN Configuration - {selectedUser}</span>
            </DialogTitle>
            <DialogDescription>
              Use the QR code for mobile devices or download the configuration file
            </DialogDescription>
          </DialogHeader>
          
          {userConfig && (
            <div className="space-y-6">
              {/* QR Code */}
              {userConfig.qr_code && (
                <div className="text-center">
                  <div className="inline-block p-4 bg-white rounded-lg border">
                    <img 
                      src={userConfig.qr_code} 
                      alt="VPN Configuration QR Code"
                      className="w-48 h-48"
                    />
                  </div>
                  <p className="text-sm text-muted-foreground mt-2">
                    Scan with WireGuard mobile app
                  </p>
                </div>
              )}

              {/* Configuration Text */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <Label>Configuration File</Label>
                  <div className="flex space-x-2">
                    <Button variant="outline" size="sm" onClick={copyConfig}>
                      {copied ? (
                        <>
                          <CheckCircle className="h-3 w-3 mr-1" />
                          Copied
                        </>
                      ) : (
                        <>
                          <Copy className="h-3 w-3 mr-1" />
                          Copy
                        </>
                      )}
                    </Button>
                    <Button variant="outline" size="sm" onClick={downloadConfig}>
                      <Download className="h-3 w-3 mr-1" />
                      Download
                    </Button>
                  </div>
                </div>
                <pre className="bg-muted p-4 rounded-md text-sm overflow-x-auto">
                  {userConfig.config_content}
                </pre>
              </div>

              <div className="flex justify-end">
                <Button onClick={() => setShowConfig(false)}>
                  Close
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}

export default VPNManager
