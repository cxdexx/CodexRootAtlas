# SQL Injection Learning Lab

A beginner-friendly educational web app built with React + Vite.

## Purpose

This app teaches:
- What a database is, and how rows, columns, and schemas work
- How applications interact with databases
- What SQL injection (SQLi) is and why it happens
- Different SQLi concepts: classic, blind, time-based, out-of-band
- Safe coding patterns and defensive mitigations

## Features

- Interactive schema explorer
- Visual app-to-database flow with safe and vulnerable modes
- Safe mock simulators for login bypass, search, blind SQLi, time-based, and outbound concepts
- Interactive quizzes and mitigation cards
- No real database, no backend, no exploit automation

## How it works

The app runs entirely in the browser using mock data and simulated query generation. It demonstrates how user input is handled and why secure patterns like parameterized queries keep SQL structure safe.

## Run locally

From `resources/sql-injection-lab`:

```bash
npm install
npm run dev
```

Then open the local URL shown in the terminal.

## Limitations

- This is a conceptual learning tool only.
- It does not connect to a database or execute real SQL.
- It does not provide exploitation scripts.
