import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class TemplateEngine {
    constructor() {
        this.templatesDir = path.join(__dirname, 'templates');
        this.stylesPath = path.join(__dirname, 'styles.css');
    }

    // Read template file
    readTemplate(templateName) {
        const templatePath = path.join(this.templatesDir, `${templateName}.html`);
        try {
            return fs.readFileSync(templatePath, 'utf8');
        } catch (error) {
            console.error(`Template not found: ${templatePath}`);
            return null;
        }
    }

    // Read CSS styles
    readStyles() {
        try {
            return fs.readFileSync(this.stylesPath, 'utf8');
        } catch (error) {
            console.error('Styles file not found');
            return '';
        }
    }

    // Simple template rendering with variable replacement
    render(templateName, data = {}) {
        let template = this.readTemplate(templateName);
        if (!template) {
            return this.renderError('Template not found');
        }

        // Replace variables in template
        Object.keys(data).forEach(key => {
            const regex = new RegExp(`\\{\\{\\s*${key}\\s*\\}\\}`, 'g');
            template = template.replace(regex, data[key]);
        });

        // Add styles
        const styles = this.readStyles();
        template = template.replace('{{STYLES}}', styles);

        return template;
    }

    // Render error page
    renderError(message, title = 'Error') {
        return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>${title} - Security Demo</title>
            <style>{{STYLES}}</style>
        </head>
        <body>
            <div class="error-container">
                <div class="error-icon">🚫</div>
                <h1>${title}</h1>
                <p>${message}</p>
                <a href="/" class="btn">Back to Home</a>
            </div>
        </body>
        </html>
        `.replace('{{STYLES}}', this.readStyles());
    }

    // Render base layout
    renderLayout(content, title = 'Security Demo', headerClass = 'header') {
        return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>${title}</title>
            <style>{{STYLES}}</style>
        </head>
        <body>
            <div class="container">
                ${content}
            </div>
        </body>
        </html>
        `.replace('{{STYLES}}', this.readStyles());
    }
}

export default new TemplateEngine(); 