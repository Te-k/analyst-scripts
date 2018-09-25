---
gophish:
    tests:
        - name: homepage
          path: /
          content: "404 page not found"
          code: 404
        - name: static
          path: /static/
          code: 200
        - name: gitignore
          path: /static/.gitignore
          code: 200
          content: "!.gitignore"
    condition: all
