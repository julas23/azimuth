import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button.jsx'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card.jsx'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { 
  Shield, 
  Network, 
  Lock, 
  AlertTriangle,
  Play,
  Square,
  RotateCcw,
  Plus,
  Trash2,
  Eye,
  Settings,
  Wifi,
  Ban,
  CheckCircle,
  XCircle,
  Activity
} from 'lucide-react'

import VPNManager from './VPNManager'

// API base URL - adjust for your backend
const API_BASE = 'http://localhost:5001/api/v1'

function NetworkLayer() {
  const [services, setServices] = useState({
    nftables: { status: 'unknown' },
    wireguard: { status: 'unknown' },
    fail2ban: { status: 'unknown' }
  })
  const [activeTab, setActiveTab] = useState('overview')
  const [loading, setLoading] = useState(false)

  // Fetch service statuses
  const fetchServiceStatus = async (serviceName) => {
    try {
      const response = await fetch(`${API_BASE}/services/${serviceName}`)
      const data = await response.json()
      return data
    } catch (error) {
      console.error(`Error fetching ${serviceName} status:`, error)
      return { status: 'error', error: error.message }
    }
  }

  const fetchAllStatuses = async () => {
    setLoading(true)
    try {
      const [nftables, wireguard, fail2ban] = await Promise.all([
        fetchServiceStatus('nftables'),
        fetchServiceStatus('wireguard'),
        fetchServiceStatus('fail2ban')
      ])
      
      setServices({
        nftables,
        wireguard,
        fail2ban
      })
    } catch (error) {
      console.error('Error fetching statuses:', error)
    } finally {
      setLoading(false)
    }
  }

  const executeServiceAction = async (serviceName, action) => {
    try {
      const response = await fetch(`${API_BASE}/services/${serviceName}/action`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ action })
      })
      
      const data = await response.json()
      
      if (response.ok) {
        // Refresh status after action
        const newStatus = await fetchServiceStatus(serviceName)
        setServices(prev => ({
          ...prev,
          [serviceName]: newStatus
        }))
      } else {
        console.error(`Error executing ${action} on ${serviceName}:`, data.error)
      }
    } catch (error) {
      console.error(`Error executing ${action} on ${serviceName}:`, error)
    }
  }

  useEffect(() => {
    fetchAllStatuses()
    // Refresh every 30 seconds
    const interval = setInterval(fetchAllStatuses, 30000)
    return () => clearInterval(interval)
  }, [])

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
      case 'error': return <AlertTriangle className="h-4 w-4" />
      default: return <Activity className="h-4 w-4" />
    }
  }

  const ServiceCard = ({ name, displayName, icon: Icon, service, color }) => (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <div className={`p-2 rounded-md ${color} text-white`}>
              <Icon className="h-4 w-4" />
            </div>
            <div>
              <CardTitle className="text-lg">{displayName}</CardTitle>
              <CardDescription className="text-sm">
                Network security service
              </CardDescription>
            </div>
          </div>
          <div className={`flex items-center space-x-1 ${getStatusColor(service.status)}`}>
            {getStatusIcon(service.status)}
            <span className="text-sm font-medium capitalize">{service.status}</span>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex space-x-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => executeServiceAction(name, 'start')}
            disabled={service.status === 'active'}
          >
            <Play className="h-3 w-3 mr-1" />
            Start
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => executeServiceAction(name, 'stop')}
            disabled={service.status === 'inactive'}
          >
            <Square className="h-3 w-3 mr-1" />
            Stop
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => executeServiceAction(name, 'reload')}
            disabled={service.status !== 'active'}
          >
            <RotateCcw className="h-3 w-3 mr-1" />
            Reload
          </Button>
        </div>
      </CardContent>
    </Card>
  )

  return (
    <div className="space-y-6">
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="interfaces">Interfaces</TabsTrigger>
          <TabsTrigger value="firewall">Firewall</TabsTrigger>
          <TabsTrigger value="vpn">VPN</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold">Network Services Status</h3>
            <Button 
              variant="outline" 
              size="sm" 
              onClick={fetchAllStatuses}
              disabled={loading}
            >
              <RotateCcw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <ServiceCard
              name="nftables"
              displayName="NFTables"
              icon={Shield}
              service={services.nftables}
              color="bg-red-500"
            />
            <ServiceCard
              name="wireguard"
              displayName="WireGuard"
              icon={Lock}
              service={services.wireguard}
              color="bg-blue-500"
            />
            <ServiceCard
              name="fail2ban"
              displayName="Fail2Ban"
              icon={Ban}
              service={services.fail2ban}
              color="bg-orange-500"
            />
          </div>

          {/* Quick Actions */}
          <Card>
            <CardHeader>
              <CardTitle>Quick Actions</CardTitle>
              <CardDescription>
                Common network management tasks
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <Button variant="outline" className="h-auto p-4 flex-col">
                  <Shield className="h-6 w-6 mb-2" />
                  <span className="text-sm">Apply Default Rules</span>
                </Button>
                <Button variant="outline" className="h-auto p-4 flex-col">
                  <Plus className="h-6 w-6 mb-2" />
                  <span className="text-sm">Add VPN User</span>
                </Button>
                <Button variant="outline" className="h-auto p-4 flex-col">
                  <Eye className="h-6 w-6 mb-2" />
                  <span className="text-sm">View Logs</span>
                </Button>
                <Button variant="outline" className="h-auto p-4 flex-col">
                  <Settings className="h-6 w-6 mb-2" />
                  <span className="text-sm">Network Config</span>
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="interfaces" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Network Interfaces</CardTitle>
              <CardDescription>
                Configure LAN and WAN interfaces
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-8 text-muted-foreground">
                <Network className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>Interface management coming soon...</p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="firewall" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Firewall Rules (NFTables)</CardTitle>
              <CardDescription>
                Manage network access rules
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-8 text-muted-foreground">
                <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>Firewall management coming soon...</p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="vpn" className="space-y-4">
          <VPNManager />
        </TabsContent>

        <TabsContent value="security" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Security & Protection (Fail2Ban)</CardTitle>
              <CardDescription>
                Monitor and manage security threats
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-8 text-muted-foreground">
                <Ban className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>Security management coming soon...</p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}

export default NetworkLayer
