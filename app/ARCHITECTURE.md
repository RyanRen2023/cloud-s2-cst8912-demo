# Application Architecture

This application has been refactored to follow a clean separation of concerns with the following structure:

## 📁 Directory Structure

```
app/
├── app.js                 # Main application entry point
├── controllers/           # Page controllers for rendering logic
│   └── pageController.js
├── routes/               # Route handlers and middleware
│   └── pageRoutes.js
├── services/             # Business logic services
│   ├── authService.js    # Authentication and authorization logic
│   └── vaultService.js   # Vault secret management
├── views/                # Template and styling
│   ├── styles.css        # Shared CSS styles
│   ├── templateEngine.js # Template rendering engine
│   └── templates/        # HTML templates
│       ├── welcome.html
│       ├── dashboard.html
│       ├── admin.html
│       ├── user.html
│       └── secrets.html
└── ARCHITECTURE.md       # This file
```

## 🏗️ Architecture Layers

### 1. **Application Layer** (`app.js`)
- **Purpose**: Application initialization and configuration
- **Responsibilities**:
  - Express app setup
  - Middleware configuration
  - Environment variable management
  - Keycloak OIDC initialization
  - Route registration

### 2. **Route Layer** (`routes/pageRoutes.js`)
- **Purpose**: HTTP route handling and request processing
- **Responsibilities**:
  - Route definition and middleware
  - Request validation
  - Authentication enforcement
  - Service coordination
  - Response handling

### 3. **Controller Layer** (`controllers/pageController.js`)
- **Purpose**: Page rendering and view logic
- **Responsibilities**:
  - Template data preparation
  - View rendering
  - Error page handling
  - Response formatting

### 4. **Service Layer** (`services/`)
- **Purpose**: Business logic and external service integration
- **Responsibilities**:
  - **authService.js**: Authentication, authorization, and user management
  - **vaultService.js**: HashiCorp Vault integration and secret management

### 5. **View Layer** (`views/`)
- **Purpose**: Presentation and templating
- **Responsibilities**:
  - **templateEngine.js**: Template rendering with variable substitution
  - **styles.css**: Shared CSS styling
  - **templates/**: HTML template files

## 🔄 Data Flow

1. **Request** → `app.js` (routing)
2. **Route Handler** → `pageRoutes.js` (request processing)
3. **Service Layer** → `services/` (business logic)
4. **Controller** → `pageController.js` (data preparation)
5. **Template Engine** → `views/templateEngine.js` (rendering)
6. **Response** → HTML page with styles

## 🎯 Benefits of This Architecture

### **Separation of Concerns**
- Each layer has a specific responsibility
- Easy to modify one layer without affecting others
- Clear boundaries between business logic and presentation

### **Maintainability**
- Modular code structure
- Easy to locate and fix issues
- Consistent patterns across the application

### **Scalability**
- Easy to add new routes, services, or templates
- Reusable components
- Clear extension points

### **Testability**
- Each layer can be tested independently
- Mock services for testing
- Isolated business logic

### **Code Reusability**
- Shared services across routes
- Common styling and templates
- Reusable authentication logic

## 🔧 Key Components

### **Template Engine**
- Simple variable substitution with `{{variable}}` syntax
- Automatic CSS injection
- Error page handling
- File-based template management

### **Authentication Service**
- Role-based access control
- Token validation
- User logging
- Country flag mapping

### **Vault Service**
- Secret retrieval
- Error handling
- Batch operations
- Configuration management

### **Page Controller**
- Template data preparation
- Role-based UI generation
- Error page rendering
- Response formatting

## 🚀 Adding New Features

### **New Page**
1. Create template in `views/templates/`
2. Add controller method in `pageController.js`
3. Add route in `pageRoutes.js`
4. Update navigation if needed

### **New Service**
1. Create service file in `services/`
2. Implement business logic
3. Import and use in routes/controllers

### **New Route**
1. Add route handler in `pageRoutes.js`
2. Implement authentication/authorization
3. Call appropriate service and controller methods

## 🔒 Security Features

- **Zero Trust Architecture**: Every request is validated
- **Role-Based Access Control**: Granular permissions
- **Token Validation**: Automatic session management
- **Secure Secret Management**: Vault integration
- **Input Validation**: Request sanitization
- **Error Handling**: Secure error responses

This architecture provides a solid foundation for a secure, maintainable, and scalable application. 