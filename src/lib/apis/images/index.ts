import { IMAGES_API_BASE_URL } from '$lib/constants';

export type ImagesConfig = {
	ENABLE_IMAGE_GENERATION: boolean;
	ENABLE_IMAGE_PROMPT_GENERATION: boolean;
	IMAGE_GENERATION_ENGINE: string;
	IMAGE_GENERATION_MODEL: string;
	IMAGE_SIZE: string | null;
	IMAGE_STEPS: number | null;
	IMAGES_OPENAI_API_BASE_URL: string;
	IMAGES_OPENAI_API_KEY: string;
	IMAGES_OPENAI_API_VERSION: string;
	IMAGES_OPENAI_API_PARAMS: object | string | null;
	IMAGE_OPENAI_USE_CONNECTION: boolean;
	IMAGE_OPENAI_CONNECTION_IDX: number;
	AUTOMATIC1111_BASE_URL: string;
	AUTOMATIC1111_API_AUTH: object | string | null;
	AUTOMATIC1111_PARAMS: object | string | null;
	COMFYUI_BASE_URL: string;
	COMFYUI_API_KEY: string;
	COMFYUI_WORKFLOW: string;
	COMFYUI_WORKFLOW_NODES: Array<object>;
	IMAGES_GEMINI_API_BASE_URL: string;
	IMAGES_GEMINI_API_KEY: string;
	IMAGES_GEMINI_ENDPOINT_METHOD: string;
	ENABLE_IMAGE_EDIT: boolean;
	IMAGE_EDIT_ENGINE: string;
	IMAGE_EDIT_MODEL: string;
	IMAGE_EDIT_SIZE: string | null;
	IMAGES_EDIT_OPENAI_API_BASE_URL: string;
	IMAGES_EDIT_OPENAI_API_KEY: string;
	IMAGES_EDIT_OPENAI_API_VERSION: string;
	IMAGE_EDIT_OPENAI_USE_CONNECTION: boolean;
	IMAGE_EDIT_OPENAI_CONNECTION_IDX: number;
	IMAGES_EDIT_GEMINI_API_BASE_URL: string;
	IMAGES_EDIT_GEMINI_API_KEY: string;
	IMAGES_EDIT_COMFYUI_BASE_URL: string;
	IMAGES_EDIT_COMFYUI_API_KEY: string;
	IMAGES_EDIT_COMFYUI_WORKFLOW: string;
	IMAGES_EDIT_COMFYUI_WORKFLOW_NODES: Array<object>;
};

export const getConfig = async (token: string = '') => {
	let error = null;

	const res = await fetch(`${IMAGES_API_BASE_URL}/config`, {
		method: 'GET',
		headers: {
			Accept: 'application/json',
			'Content-Type': 'application/json',
			...(token && { authorization: `Bearer ${token}` })
		}
	})
		.then(async (res) => {
			if (!res.ok) throw await res.json();
			return res.json();
		})
		.catch((err) => {
			console.error(err);
			if ('detail' in err) {
				error = err.detail;
			} else {
				error = 'Server connection failed';
			}
			return null;
		});

	if (error) {
		throw error;
	}

	return res;
};

export const updateConfig = async (token: string = '', config: ImagesConfig) => {
	let error = null;

	const res = await fetch(`${IMAGES_API_BASE_URL}/config/update`, {
		method: 'POST',
		headers: {
			Accept: 'application/json',
			'Content-Type': 'application/json',
			...(token && { authorization: `Bearer ${token}` })
		},
		body: JSON.stringify({
			...config
		})
	})
		.then(async (res) => {
			if (!res.ok) throw await res.json();
			return res.json();
		})
		.catch((err) => {
			console.error(err);
			if ('detail' in err) {
				error = err.detail;
			} else {
				error = 'Server connection failed';
			}
			return null;
		});

	if (error) {
		throw error;
	}

	return res;
};

export const verifyConfigUrl = async (token: string = '') => {
	let error = null;

	const res = await fetch(`${IMAGES_API_BASE_URL}/config/url/verify`, {
		method: 'GET',
		headers: {
			Accept: 'application/json',
			'Content-Type': 'application/json',
			...(token && { authorization: `Bearer ${token}` })
		}
	})
		.then(async (res) => {
			if (!res.ok) throw await res.json();
			return res.json();
		})
		.catch((err) => {
			console.error(err);
			if ('detail' in err) {
				error = err.detail;
			} else {
				error = 'Server connection failed';
			}
			return null;
		});

	if (error) {
		throw error;
	}

	return res;
};

export const getImageGenerationConfig = async (token: string = '') => {
	let error = null;

	const res = await fetch(`${IMAGES_API_BASE_URL}/image/config`, {
		method: 'GET',
		headers: {
			Accept: 'application/json',
			'Content-Type': 'application/json',
			...(token && { authorization: `Bearer ${token}` })
		}
	})
		.then(async (res) => {
			if (!res.ok) throw await res.json();
			return res.json();
		})
		.catch((err) => {
			console.error(err);
			if ('detail' in err) {
				error = err.detail;
			} else {
				error = 'Server connection failed';
			}
			return null;
		});

	if (error) {
		throw error;
	}

	return res;
};

export const updateImageGenerationConfig = async (token: string = '', config: object) => {
	let error = null;

	const res = await fetch(`${IMAGES_API_BASE_URL}/image/config/update`, {
		method: 'POST',
		headers: {
			Accept: 'application/json',
			'Content-Type': 'application/json',
			...(token && { authorization: `Bearer ${token}` })
		},
		body: JSON.stringify({ ...config })
	})
		.then(async (res) => {
			if (!res.ok) throw await res.json();
			return res.json();
		})
		.catch((err) => {
			console.error(err);
			if ('detail' in err) {
				error = err.detail;
			} else {
				error = 'Server connection failed';
			}
			return null;
		});

	if (error) {
		throw error;
	}

	return res;
};

export const getImageGenerationModels = async (token: string = '') => {
	let error = null;

	const res = await fetch(`${IMAGES_API_BASE_URL}/models`, {
		method: 'GET',
		headers: {
			Accept: 'application/json',
			'Content-Type': 'application/json',
			...(token && { authorization: `Bearer ${token}` })
		}
	})
		.then(async (res) => {
			if (!res.ok) throw await res.json();
			return res.json();
		})
		.catch((err) => {
			console.error(err);
			if ('detail' in err) {
				error = err.detail;
			} else {
				error = 'Server connection failed';
			}
			return null;
		});

	if (error) {
		throw error;
	}

	return res;
};

export const imageGenerations = async (token: string = '', prompt: string) => {
	let error = null;

	const res = await fetch(`${IMAGES_API_BASE_URL}/generations`, {
		method: 'POST',
		headers: {
			Accept: 'application/json',
			'Content-Type': 'application/json',
			...(token && { authorization: `Bearer ${token}` })
		},
		body: JSON.stringify({
			prompt: prompt
		})
	})
		.then(async (res) => {
			if (!res.ok) throw await res.json();
			return res.json();
		})
		.catch((err) => {
			console.error(err);
			if ('detail' in err) {
				if (Array.isArray(err.detail)) {
					error = err.detail.map((e: { msg?: string }) => e.msg || JSON.stringify(e)).join(', ');
				} else {
					error = err.detail;
				}
			} else {
				error = 'Server connection failed';
			}
			return null;
		});

	if (error) {
		throw error;
	}

	return res;
};

export const imageEdits = async (
	token: string = '',
	images: string | string[],
	prompt: string,
	model?: string,
	size?: string,
	n?: number,
	background?: string
) => {
	let error = null;

	const res = await fetch(`${IMAGES_API_BASE_URL}/edit`, {
		method: 'POST',
		headers: {
			Accept: 'application/json',
			'Content-Type': 'application/json',
			...(token && { authorization: `Bearer ${token}` })
		},
		body: JSON.stringify({
			form_data: {
				image: images,
				prompt,
				...(model && { model }),
				...(size && { size }),
				...(n && { n }),
				...(background && { background })
			}
		})
	})
		.then(async (res) => {
			if (!res.ok) throw await res.json();
			return res.json();
		})
		.catch((err) => {
			console.error(err);
			if ('detail' in err) {
				if (Array.isArray(err.detail)) {
					error = err.detail.map((e: { msg?: string }) => e.msg || JSON.stringify(e)).join(', ');
				} else {
					error = err.detail;
				}
			} else {
				error = 'Server connection failed';
			}
			return null;
		});

	if (error) {
		throw error;
	}

	return res;
};
