import { useState } from 'react'
import { Button } from '@/components/ui/button.jsx'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card.jsx'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { 
  Shield, 
  HardDrive, 
  Monitor, 
  Package, 
  Brain,
  Network,
  Router,
  Lock,
  AlertTriangle,
  Server,
  Activity
} from 'lucide-react'
import './App.css'

// Import components for each layer
import NetworkLayer from './components/NetworkLayer'

function App() {
  const [activeLayer, setActiveLayer] = useState('network')

  const layers = [
    {
      id: 'network',
      name: 'Network',
      icon: Network,
      description: 'Firewall, VPN & Security',
      services: ['NFTables', 'WireGuard', 'Fail2Ban'],
      color: 'bg-red-500'
    },
    {
      id: 'storage',
      name: 'Storage',
      icon: HardDrive,
      description: 'File Systems & Sharing',
      services: ['NFS', 'Samba', 'Persistent Volumes'],
      color: 'bg-blue-500'
    },
    {
      id: 'virtualization',
      name: 'Virtualization',
      icon: Monitor,
      description: 'Virtual Machines',
      services: ['KVM', 'QEMU'],
      color: 'bg-green-500'
    },
    {
      id: 'apps',
      name: 'Applications',
      icon: Package,
      description: 'Container Orchestration',
      services: ['K3S', 'Docker', 'Immich', 'Jellyfin', 'Nextcloud'],
      color: 'bg-purple-500'
    },
    {
      id: 'ai',
      name: 'AI Services',
      icon: Brain,
      description: 'Machine Learning',
      services: ['Ollama', 'Local Models'],
      color: 'bg-orange-500'
    }
  ]

  const renderLayerContent = () => {
    switch (activeLayer) {
      case 'network':
        return <NetworkLayer />
      case 'storage':
        return <div className="p-6 text-center text-muted-foreground">Storage layer coming soon...</div>
      case 'virtualization':
        return <div className="p-6 text-center text-muted-foreground">Virtualization layer coming soon...</div>
      case 'apps':
        return <div className="p-6 text-center text-muted-foreground">Applications layer coming soon...</div>
      case 'ai':
        return <div className="p-6 text-center text-muted-foreground">AI Services layer coming soon...</div>
      default:
        return <div className="p-6 text-center text-muted-foreground">Select a layer to manage</div>
    }
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b bg-card">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Server className="h-8 w-8 text-primary" />
              <div>
                <h1 className="text-2xl font-bold">Home Server Admin</h1>
                <p className="text-sm text-muted-foreground">Complete Infrastructure Management</p>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <Badge variant="outline" className="flex items-center space-x-1">
                <Activity className="h-3 w-3" />
                <span>System Online</span>
              </Badge>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-4 py-6">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Sidebar - Layer Navigation */}
          <div className="lg:col-span-1">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Shield className="h-5 w-5" />
                  <span>Infrastructure Layers</span>
                </CardTitle>
                <CardDescription>
                  Manage your home server stack
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-2">
                {layers.map((layer) => {
                  const IconComponent = layer.icon
                  return (
                    <Button
                      key={layer.id}
                      variant={activeLayer === layer.id ? "default" : "ghost"}
                      className="w-full justify-start h-auto p-3"
                      onClick={() => setActiveLayer(layer.id)}
                    >
                      <div className="flex items-start space-x-3">
                        <div className={`p-2 rounded-md ${layer.color} text-white`}>
                          <IconComponent className="h-4 w-4" />
                        </div>
                        <div className="text-left">
                          <div className="font-medium">{layer.name}</div>
                          <div className="text-xs text-muted-foreground">
                            {layer.description}
                          </div>
                          <div className="flex flex-wrap gap-1 mt-1">
                            {layer.services.slice(0, 2).map((service) => (
                              <Badge key={service} variant="secondary" className="text-xs">
                                {service}
                              </Badge>
                            ))}
                            {layer.services.length > 2 && (
                              <Badge variant="secondary" className="text-xs">
                                +{layer.services.length - 2}
                              </Badge>
                            )}
                          </div>
                        </div>
                      </div>
                    </Button>
                  )
                })}
              </CardContent>
            </Card>
          </div>

          {/* Main Content Area */}
          <div className="lg:col-span-3">
            <Card className="min-h-[600px]">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center space-x-2">
                      {(() => {
                        const currentLayer = layers.find(l => l.id === activeLayer)
                        const IconComponent = currentLayer?.icon || Network
                        return (
                          <>
                            <div className={`p-2 rounded-md ${currentLayer?.color || 'bg-gray-500'} text-white`}>
                              <IconComponent className="h-5 w-5" />
                            </div>
                            <span>{currentLayer?.name || 'Select Layer'} Management</span>
                          </>
                        )
                      })()}
                    </CardTitle>
                    <CardDescription>
                      {layers.find(l => l.id === activeLayer)?.description || 'Choose a layer to manage'}
                    </CardDescription>
                  </div>
                  <div className="flex space-x-2">
                    <Button variant="outline" size="sm">
                      <AlertTriangle className="h-4 w-4 mr-2" />
                      Logs
                    </Button>
                    <Button variant="outline" size="sm">
                      <Router className="h-4 w-4 mr-2" />
                      Status
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                {renderLayerContent()}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  )
}

export default App
