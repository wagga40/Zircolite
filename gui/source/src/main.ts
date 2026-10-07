import { mount } from 'svelte';
import App from './App.svelte';
import './app.css';

const target = document.getElementById('app');
if (target === null) throw new Error('index.html has no #app element');
mount(App, { target });
