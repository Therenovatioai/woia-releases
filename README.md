# WOIA

Crea y actualiza tu workspace con el ejecutable Windows x64.

## Descargar

Abre [Releases](https://github.com/Therenovatioai/woia-releases/releases), elige una versión y descarga el paquete Windows x64, junto con woia-updates.json y SHA256SUMS. Las primeras versiones son prerreleases. No necesitas Git, Bun ni acceso al repositorio de desarrollo. macOS y Linux no están verificados ni disponibles.

Comprueba el SHA-256 antes de extraer el tar en una carpeta nueva. Usa INSTALL.md para crear un workspace y UPGRADE.md para actualizar uno existente. El catálogo de cada release indica el origen compatible; no saltes transiciones ni uses init para actualizar.

Puedes pedir al agente: “Prepara la actualización de mi workspace desde este canal, conserva un respaldo y muéstrame la propuesta antes de aplicarla”. El agente usa el ejecutable descargado y solicita autorización para el digest de la propuesta concreta.

Los paquetes incluyen instrucciones, recursos operacionales y licencias. La evidencia de compatibilidad se limita a Windows x64. Lee LIMITATIONS.md; no desactives las protecciones de tu equipo. Mantén tus respaldos y datos privados fuera de este repositorio.
