import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

export function ShadcnDemo() {
  return (
    <div className="container mx-auto p-8 space-y-8">
      <div className="text-center space-y-4">
        <h1 className="text-4xl font-bold tracking-tight">
          Shadcn UI + Tailwind CSS v4 Demo
        </h1>
        <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
          This demonstrates Shadcn UI components working seamlessly with Tailwind CSS v4 
          in your Tauri application. All components use CSS variables for theming and 
          are fully compatible with both light and dark modes.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {/* Button Examples */}
        <Card>
          <CardHeader>
            <CardTitle>Button Variants</CardTitle>
            <CardDescription>
              Different button styles and sizes
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Button className="w-full">Default Button</Button>
              <Button variant="secondary" className="w-full">
                Secondary Button
              </Button>
              <Button variant="outline" className="w-full">
                Outline Button
              </Button>
              <Button variant="ghost" className="w-full">
                Ghost Button
              </Button>
            </div>
            <div className="flex gap-2">
              <Button size="sm">Small</Button>
              <Button size="default">Default</Button>
              <Button size="lg">Large</Button>
            </div>
          </CardContent>
        </Card>

        {/* Form Example */}
        <Card>
          <CardHeader>
            <CardTitle>Form Components</CardTitle>
            <CardDescription>
              Input fields with labels
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="Enter your email"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                placeholder="Enter your password"
              />
            </div>
          </CardContent>
          <CardFooter>
            <Button className="w-full">Sign In</Button>
          </CardFooter>
        </Card>

        {/* Tailwind v4 Features */}
        <Card>
          <CardHeader>
            <CardTitle>Tailwind v4 Features</CardTitle>
            <CardDescription>
              Modern CSS features working with Shadcn
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="p-4 rounded-lg bg-gradient-to-r from-blue-500 to-purple-600 text-white">
              <p className="font-semibold">CSS Gradients</p>
              <p className="text-sm opacity-90">
                Tailwind v4 gradients work perfectly
              </p>
            </div>
            <div className="p-4 rounded-lg border-2 border-dashed border-border">
              <p className="font-semibold">CSS Variables</p>
              <p className="text-sm text-muted-foreground">
                Theme colors using CSS variables
              </p>
            </div>
            <div className="grid grid-cols-3 gap-2">
              <div className="h-8 rounded bg-primary"></div>
              <div className="h-8 rounded bg-secondary"></div>
              <div className="h-8 rounded bg-accent"></div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Theme Toggle Demo */}
      <Card>
        <CardHeader>
          <CardTitle>Theme Compatibility</CardTitle>
          <CardDescription>
            Shadcn UI components automatically adapt to light/dark themes using CSS variables.
            Toggle your system theme to see the components update automatically.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-lg bg-background border">
              <h4 className="font-semibold mb-2">Light Theme Colors</h4>
              <div className="space-y-2 text-sm">
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded bg-primary"></div>
                  <span>Primary</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded bg-secondary"></div>
                  <span>Secondary</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded bg-muted"></div>
                  <span>Muted</span>
                </div>
              </div>
            </div>
            <div className="p-4 rounded-lg bg-card border">
              <h4 className="font-semibold mb-2">Component States</h4>
              <div className="space-y-2">
                <Button variant="outline" className="w-full" disabled>
                  Disabled State
                </Button>
                <Input placeholder="Focus me for ring effect" />
                <Button variant="destructive" size="sm">
                  Destructive Action
                </Button>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
